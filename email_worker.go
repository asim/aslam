package main

import (
	"encoding/json"
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
	log.Println("Email worker: can be disabled from /admin")
	
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
	// Check if disabled via admin
	if db.GetSetting("gmail_enabled") == "false" {
		return
	}
	
	log.Println("Email worker: checking inbox")
	
	emails, err := tools.FetchEmails(20, false) // Fetch recent emails (not just unread - we track by Message-ID)
	if err != nil {
		log.Printf("Email worker: failed to fetch emails: %v", err)
		return
	}

	if len(emails) == 0 {
		log.Println("Email worker: no emails")
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
	
	// Skip emails from ourselves (outbound)
	if strings.EqualFold(senderEmail, os.Getenv("GMAIL_USER")) {
		return
	}
	
	// Check if sender is allowed
	if !emailAllowedSenders[strings.ToLower(senderEmail)] {
		log.Printf("Email worker: ignoring email from unauthorized sender: %s", senderEmail)
		return
	}

	// Check if we've already processed this email
	if email.MessageID != "" && db.EmailExists(email.MessageID) {
		log.Printf("Email worker: email already logged: %s", email.MessageID)
		tools.MarkAsRead(email.UID)
		return
	}

	log.Printf("Email worker: queueing email from %s: %s", senderEmail, email.Subject)

	// Determine thread ID
	threadID := determineThreadID(email)

	// Log the email first
	_, err := db.LogEmail(
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
		return
	}

	// Add the email as a user message (just the content, context is in the conversation)
	userMessage := email.Body
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		log.Printf("Email worker: failed to add message: %v", err)
		return
	}

	// Create pending task for processing
	metadata, _ := json.Marshal(map[string]string{
		"from":       senderEmail,
		"subject":    email.Subject,
		"message_id": email.MessageID,
		"thread_id":  threadID,
		"references": email.References,
	})
	
	_, err = db.CreatePendingTask("email", convID, email.MessageID, string(metadata))
	if err != nil {
		log.Printf("Email worker: failed to create pending task: %v", err)
		return
	}

	// Mark original as read (we've queued it for processing)
	tools.MarkAsRead(email.UID)

	log.Printf("Email worker: queued email from %s for processing", senderEmail)
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
	// If this is a reply, look up the thread by In-Reply-To
	if email.InReplyTo != "" {
		// Check if we have a thread with this message ID
		if thread, err := db.GetEmailThreadByMessageID(email.InReplyTo); err == nil {
			log.Printf("Email worker: found thread %s for In-Reply-To %s", thread.ThreadID, email.InReplyTo)
			return thread.ThreadID
		}
		// Check references
		if email.References != "" {
			refs := strings.Fields(email.References)
			for _, ref := range refs {
				if thread, err := db.GetEmailThreadByMessageID(ref); err == nil {
					log.Printf("Email worker: found thread %s for reference %s", thread.ThreadID, ref)
					return thread.ThreadID
				}
			}
		}
		log.Printf("Email worker: no thread found for In-Reply-To %s", email.InReplyTo)
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


