package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"aslam/db"
	"aslam/tools"
)

var emailAllowedSenders map[string]bool

func startEmailWorker() {
	// Build allowed senders map
	emailAllowedSenders = make(map[string]bool)
	for email := range allowedEmails {
		emailAllowedSenders[email] = true
	}

	// Check if email is configured
	if os.Getenv("GMAIL_USER") == "" || os.Getenv("GMAIL_APP_PASSWORD") == "" {
		log.Println("Email worker: GMAIL credentials not configured, skipping")
		return
	}

	log.Println("Email worker: starting (checking every 2 minutes)")
	
	// Initial check after 30 seconds
	time.AfterFunc(30*time.Second, func() {
		checkInbox()
	})

	// Then check every 2 minutes
	ticker := time.NewTicker(2 * time.Minute)
	go func() {
		for range ticker.C {
			checkInbox()
		}
	}()
}

func checkInbox() {
	log.Println("Email worker: checking inbox")
	
	emails, err := tools.FetchEmails(20, true) // Fetch up to 20 unread
	if err != nil {
		log.Printf("Email worker: failed to fetch emails: %v", err)
		return
	}

	if len(emails) == 0 {
		log.Println("Email worker: no unread emails")
		return
	}

	log.Printf("Email worker: found %d unread emails", len(emails))

	for _, email := range emails {
		processEmail(email)
	}
}

func processEmail(email tools.Email) {
	// Extract sender email address
	senderEmail := extractEmail(email.From)
	
	// Check if sender is allowed
	if !emailAllowedSenders[strings.ToLower(senderEmail)] {
		log.Printf("Email worker: ignoring email from unauthorized sender: %s", senderEmail)
		// Mark as read to avoid processing again
		tools.MarkAsRead(email.UID)
		return
	}

	// Check if we've already processed this email
	if email.MessageID != "" && db.EmailExists(email.MessageID) {
		log.Printf("Email worker: email already processed: %s", email.MessageID)
		tools.MarkAsRead(email.UID)
		return
	}

	log.Printf("Email worker: processing email from %s: %s", senderEmail, email.Subject)

	// Determine thread ID (use In-Reply-To or References, or create new from MessageID)
	threadID := determineThreadID(email)

	// Log the email first (status: pending)
	logID, err := db.LogEmail(
		email.MessageID,
		threadID,
		"inbound",
		senderEmail,
		os.Getenv("GMAIL_USER"),
		email.Subject,
		email.Body,
		"pending",
	)
	if err != nil {
		log.Printf("Email worker: failed to log email: %v", err)
		return
	}

	// Find or create conversation for this thread
	convID, err := getOrCreateConversation(threadID, email.Subject, senderEmail)
	if err != nil {
		log.Printf("Email worker: failed to get/create conversation: %v", err)
		db.UpdateEmailStatus(logID, "failed", err.Error())
		return
	}

	// Add the email as a user message
	userMessage := fmt.Sprintf("[Email from %s]\nSubject: %s\n\n%s", email.From, email.Subject, email.Body)
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		log.Printf("Email worker: failed to add message: %v", err)
		db.UpdateEmailStatus(logID, "failed", err.Error())
		return
	}

	// Get conversation history
	messages, err := db.GetMessages(convID)
	if err != nil {
		log.Printf("Email worker: failed to get messages: %v", err)
		db.UpdateEmailStatus(logID, "failed", err.Error())
		return
	}

	// Call Claude
	response, err := callClaudeForEmail(messages)
	if err != nil {
		log.Printf("Email worker: Claude failed: %v", err)
		db.UpdateEmailStatus(logID, "failed", err.Error())
		return
	}

	// Save assistant response
	if err := db.AddMessage(convID, "assistant", response); err != nil {
		log.Printf("Email worker: failed to save response: %v", err)
	}

	// Send reply email
	replySubject := email.Subject
	if !strings.HasPrefix(strings.ToLower(replySubject), "re:") {
		replySubject = "Re: " + replySubject
	}

	// Build references chain
	references := email.References
	if references != "" && email.MessageID != "" {
		references = references + " " + email.MessageID
	} else if email.MessageID != "" {
		references = email.MessageID
	}

	err = tools.SendEmailThreaded(senderEmail, replySubject, response, email.MessageID, references)
	if err != nil {
		log.Printf("Email worker: failed to send reply: %v", err)
		db.UpdateEmailStatus(logID, "failed", err.Error())
		return
	}

	// Log the outbound email
	db.LogEmail("", threadID, "outbound", os.Getenv("GMAIL_USER"), senderEmail, replySubject, response, "processed")

	// Update thread
	db.UpdateEmailThread(threadID, email.MessageID)

	// Mark original as read
	tools.MarkAsRead(email.UID)

	// Mark as processed
	db.UpdateEmailStatus(logID, "processed", "")

	log.Printf("Email worker: replied to %s", senderEmail)
}

func extractEmail(from string) string {
	// Handle "Name <email@example.com>" format
	if idx := strings.Index(from, "<"); idx != -1 {
		end := strings.Index(from, ">")
		if end > idx {
			return strings.TrimSpace(from[idx+1 : end])
		}
	}
	return strings.TrimSpace(from)
}

func determineThreadID(email tools.Email) string {
	// If this is a reply, use the In-Reply-To as thread ID
	if email.InReplyTo != "" {
		// Check if we have a thread with this message
		if thread, err := db.GetEmailThread(email.InReplyTo); err == nil {
			return thread.ThreadID
		}
		// Check references
		if email.References != "" {
			refs := strings.Fields(email.References)
			for _, ref := range refs {
				if thread, err := db.GetEmailThread(ref); err == nil {
					return thread.ThreadID
				}
			}
		}
	}
	
	// New thread - use this message's ID
	if email.MessageID != "" {
		return email.MessageID
	}
	
	// Fallback
	return fmt.Sprintf("thread-%d", time.Now().UnixNano())
}

func getOrCreateConversation(threadID, subject, sender string) (int64, error) {
	// Check if thread exists
	thread, err := db.GetEmailThread(threadID)
	if err == nil {
		return thread.ConversationID, nil
	}

	// Create new conversation
	title := fmt.Sprintf("Email: %s (from %s)", subject, sender)
	convID, err := db.CreateConversation(title)
	if err != nil {
		return 0, err
	}

	// Create thread mapping
	err = db.CreateEmailThread(threadID, convID, "")
	if err != nil {
		return 0, err
	}

	return convID, nil
}

// callClaudeForEmail uses the same generateResponse as chat
// Email is just another input channel - same agent, same tools
func callClaudeForEmail(messages []db.Message) (string, error) {
	return generateResponse(messages)
}
