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

func startEmailWorker() {
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

// emailBatchLimit caps how many messages one poll will pull into memory.
// Anything beyond it stays unread and is picked up on the next cycle.
const emailBatchLimit = 50

func checkInbox() {
	// Check if disabled via admin
	if db.GetSetting("gmail_enabled") == "false" {
		return
	}

	log.Println("Email worker: checking inbox")

	// One session for the whole poll: fetching and flagging over a single
	// connection instead of reconnecting per message.
	session, err := tools.Connect()
	if err != nil {
		log.Printf("Email worker: failed to connect: %v", err)
		return
	}
	defer session.Close()

	emails, err := session.FetchUnread(emailBatchLimit)
	if err != nil {
		log.Printf("Email worker: failed to fetch emails: %v", err)
		return
	}

	if len(emails) == 0 {
		log.Println("Email worker: no emails")
		return
	}

	log.Printf("Email worker: found %d unread emails", len(emails))

	// Collect the messages we finished with — whether queued or deliberately
	// dropped — and flag them in one round-trip. Anything left unflagged (a
	// transient failure) stays unread and is retried next cycle; anything
	// dropped must be flagged or it would clog the unread window forever.
	var handled []uint32
	for _, email := range emails {
		if processEmail(email) {
			handled = append(handled, email.UID)
		}
	}

	if err := session.MarkRead(handled...); err != nil {
		log.Printf("Email worker: failed to mark %d emails as read: %v", len(handled), err)
	}
}

// processEmail handles one message. It reports whether the message is finished
// with — either queued for a reply or intentionally dropped — so the caller can
// flag it as read. A false return means a transient failure worth retrying, so
// the message is left unread.
func processEmail(email tools.Email) bool {
	// Extract sender email address
	senderEmail := extractEmail(email.From)

	// Skip emails from ourselves (outbound)
	if strings.EqualFold(senderEmail, os.Getenv("GMAIL_USER")) {
		return true
	}

	// Check if sender is allowed
	if !db.IsUser(strings.ToLower(senderEmail)) {
		log.Printf("Email worker: ignoring email from unauthorized sender: %s", senderEmail)
		return true
	}

	// The allowlist above trusts the From header, which is trivially forged.
	// Require the receiving server to have authenticated the sending domain
	// before letting a message reach the agent and its tools.
	if !allowUnverifiedSenders() {
		if ok, reason := tools.VerifyAuthResults(email.AuthResults, senderEmail); !ok {
			log.Printf("Email worker: rejecting unauthenticated email claiming to be from %s: %s", senderEmail, reason)
			return true
		}
	}

	// Check if we've already processed this email
	if email.MessageID != "" && db.EmailExists(email.MessageID) {
		log.Printf("Email worker: email already logged: %s", email.MessageID)
		return true
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
		return false
	}

	// Find or create conversation for this thread
	convID, err := getOrCreateConversation(threadID, email.Subject, senderEmail)
	if err != nil {
		log.Printf("Email worker: failed to get/create conversation: %v", err)
		return false
	}

	// Add the email as a user message (just the content, context is in the conversation)
	userMessage := email.Body
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		log.Printf("Email worker: failed to add message: %v", err)
		return false
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
		return false
	}

	log.Printf("Email worker: queued email from %s for processing", senderEmail)
	return true
}

// allowUnverifiedSenders disables sender authentication. Off by default: it
// leaves the allowlist trusting a forgeable From header, so it is only for
// receiving servers that do not add an Authentication-Results header.
func allowUnverifiedSenders() bool {
	return strings.EqualFold(os.Getenv("EMAIL_ALLOW_UNVERIFIED"), "true")
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

	// Create new conversation (use sender's user ID if they exist)
	title := fmt.Sprintf("Email: %s (from %s)", subject, sender)
	senderUserID := db.GetUserID(strings.ToLower(sender))
	convID, err := db.CreateConversation(title, senderUserID)
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


