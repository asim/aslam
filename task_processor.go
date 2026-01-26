package main

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"aslam/db"
	"aslam/tools"
)

// startTaskProcessor runs on startup and periodically to process pending tasks
func startTaskProcessor() {
	// Reset any tasks that were processing when we crashed/restarted
	if err := db.ResetStaleTasks(); err != nil {
		log.Printf("Task processor: failed to reset stale tasks: %v", err)
	}

	// Process pending tasks immediately
	go processPendingTasks()

	// Then check every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			processPendingTasks()
		}
	}()

	log.Println("Task processor: started")
}

func processPendingTasks() {
	tasks, err := db.GetPendingTasks()
	if err != nil {
		log.Printf("Task processor: failed to get pending tasks: %v", err)
		return
	}

	if len(tasks) == 0 {
		return
	}

	log.Printf("Task processor: found %d pending tasks", len(tasks))

	for _, task := range tasks {
		processTask(task)
	}
}

func processTask(task db.PendingTask) {
	log.Printf("Task processor: processing task %d (channel=%s, conv=%d, attempt=%d/%d)",
		task.ID, task.Channel, task.ConversationID, task.Attempts+1, task.MaxAttempts)

	// Mark as processing
	if err := db.MarkTaskProcessing(task.ID); err != nil {
		log.Printf("Task processor: failed to mark task %d as processing: %v", task.ID, err)
		return
	}

	var err error
	switch task.Channel {
	case "chat", "api":
		err = processChatTask(task)
	case "email":
		err = processEmailTask(task)
	default:
		log.Printf("Task processor: unknown channel %s for task %d", task.Channel, task.ID)
		db.MarkTaskFailed(task.ID, "unknown channel")
		return
	}

	if err != nil {
		log.Printf("Task processor: task %d failed: %v", task.ID, err)
		if task.Attempts+1 >= task.MaxAttempts {
			db.MarkTaskFailed(task.ID, err.Error())
		} else {
			db.UpdateTaskStatus(task.ID, "pending", err.Error())
		}
		return
	}

	db.MarkTaskCompleted(task.ID)
	log.Printf("Task processor: task %d completed", task.ID)
}

func processChatTask(task db.PendingTask) error {
	// Get conversation messages
	messages, err := db.GetMessages(task.ConversationID)
	if err != nil {
		return err
	}

	// Check if there's already an assistant response after the last user message
	// (in case we crashed after generating but before marking complete)
	if len(messages) > 0 && messages[len(messages)-1].Role == "assistant" {
		log.Printf("Task processor: task %d already has response, marking complete", task.ID)
		return nil
	}

	// Generate response
	response, err := generateResponse(messages)
	if err != nil {
		return err
	}

	// Save response
	return db.AddMessage(task.ConversationID, "assistant", response)
}

func processEmailTask(task db.PendingTask) error {
	// Parse metadata for email-specific info
	var meta struct {
		From       string `json:"from"`
		Subject    string `json:"subject"`
		MessageID  string `json:"message_id"`
		ThreadID   string `json:"thread_id"`
		References string `json:"references"`
	}
	if task.Metadata != "" {
		json.Unmarshal([]byte(task.Metadata), &meta)
	}

	// Set user context from email sender
	currentUserContext = &UserContext{Email: meta.From, Name: "", ConversationID: task.ConversationID}

	// Get conversation messages
	messages, err := db.GetMessages(task.ConversationID)
	if err != nil {
		return err
	}

	// Check if already responded
	if len(messages) > 0 && messages[len(messages)-1].Role == "assistant" {
		// Response generated, but maybe email not sent?
		// For now, assume if response exists, we're good
		log.Printf("Task processor: email task %d already has response", task.ID)
		return nil
	}

	// Generate response
	response, err := generateResponse(messages)
	if err != nil {
		return err
	}

	// Save response
	if err := db.AddMessage(task.ConversationID, "assistant", response); err != nil {
		return err
	}

	// Send reply email
	replySubject := meta.Subject
	if !strings.HasPrefix(strings.ToLower(replySubject), "re:") {
		replySubject = "Re: " + replySubject
	}

	references := meta.References
	if references != "" && meta.MessageID != "" {
		references = references + " " + meta.MessageID
	} else if meta.MessageID != "" {
		references = meta.MessageID
	}

	if _, err := tools.SendEmailThreaded(meta.From, replySubject, response, meta.MessageID, references); err != nil {
		return err
	}

	// Log outbound email
	db.LogEmail("", meta.ThreadID, "outbound", "assistant@aslam.org", meta.From, replySubject, response, "processed")

	// Update thread
	if meta.ThreadID != "" {
		db.UpdateEmailThread(meta.ThreadID, meta.MessageID)
	}

	// Mark inbound email as processed
	db.UpdateEmailStatusByMessageID(meta.MessageID, "processed", "")

	log.Printf("Task processor: sent email reply to %s", meta.From)

	return nil
}
