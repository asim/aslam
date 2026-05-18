package tools

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// Storage interface for saving/retrieving knowledge
type Storage interface {
	SaveEntry(entryType, title, content, metadata string) (int64, error)
	GetEntryByTitle(entryType, title string) (map[string]interface{}, error)
	SearchEntries(query string) ([]map[string]interface{}, error)
	SearchIslamQA(query string) ([]map[string]interface{}, error)
}

// NoteStorage interface for note operations
type NoteStorage interface {
	AddNoteItem(title, content string, userID int64) (int64, error)
	SearchNotes(query string, userID int64) ([]map[string]interface{}, error)
	GetNoteItem(id int64) (map[string]interface{}, error)
	UpdateNoteItem(id int64, updates map[string]interface{}) error
}

var store Storage
var noteStore NoteStorage

// getCurrentUserID returns the current user's ID for tool calls
var getCurrentUserID func() int64

// SetCurrentUserIDGetter sets the function to get the current user ID
func SetCurrentUserIDGetter(fn func() int64) {
	getCurrentUserID = fn
}

// SetStorage sets the storage backend
func SetStorage(s Storage) {
	store = s
}

// SetNoteStorage sets the note storage backend
func SetNoteStorage(v NoteStorage) {
	noteStore = v
}

// IntegrationChecker checks if an integration is enabled
type IntegrationChecker func(name string) bool

var isIntegrationEnabled IntegrationChecker

// SetIntegrationChecker sets the function to check if integrations are enabled
func SetIntegrationChecker(checker IntegrationChecker) {
	isIntegrationEnabled = checker
}

// EmailThreadCallback is called when an email is sent to create thread mapping
type EmailThreadCallback func(messageID string, to, subject string)

var onEmailSent EmailThreadCallback

// SetEmailSentCallback sets the callback for when emails are sent
func SetEmailSentCallback(cb EmailThreadCallback) {
	onEmailSent = cb
}

// ToolDefinition for Anthropic API
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

// GetTools returns all available tool definitions
func GetTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "fetch",
			Description: "Fetch the content of a URL (webpage, API, GitHub repo, etc). The content is automatically saved to memory for future recall. Use this to look up information from websites.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"url": map[string]interface{}{
						"type":        "string",
						"description": "The URL to fetch",
					},
				},
				"required": []string{"url"},
			},
		},
		{
			Name:        "search",
			Description: "Search the knowledge base for information. Use this to find previously fetched URLs, saved notes, or any stored knowledge. Search by keywords, URL, domain, or topic.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query - keywords, URL, domain, or topic to recall",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "store",
			Description: "Save something to the knowledge base for later retrieval. Use this to store facts, notes, or information the user wants kept.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Short title or key for this entry",
					},
					"content": map[string]interface{}{
						"type":        "string",
						"description": "The information to store",
					},
				},
				"required": []string{"title", "content"},
			},
		},
		{
			Name:        "reminder",
			Description: "Search Islamic sources (Quran, Hadith, Names of Allah) for authoritative answers. Use this when discussing Islamic topics, questions about the Prophet Muhammad (PBUH), Allah, religious rulings, or Quranic/Hadith references. Returns summarised answers with source references. Note: This can be slow.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "The Islamic question or topic to search for",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "wikipedia",
			Description: "Search Wikipedia for factual information, definitions, concepts, history, and reference material. Use this for background knowledge, understanding terms, or researching topics. Returns article summaries with links.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "The topic or term to search for on Wikipedia",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "www",
			Description: "Search the web for current information. Use this for recent news, current prices, latest updates, or any time-sensitive information that may not be in your training data. Returns search results from Brave Search.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "The search query",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "email_check",
			Description: "Check the assistant's email inbox (assistant@aslam.org). Returns recent emails with sender, subject, and body. Use this when the user asks about emails or wants to check their inbox.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"unread_only": map[string]interface{}{
						"type":        "boolean",
						"description": "Only return unread emails (default: false)",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of emails to return (default: 10)",
					},
				},
			},
		},
		{
			Name:        "email_send",
			Description: "Send an email from assistant@aslam.org. Use this when the user wants to send an email or reply to someone.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"to": map[string]interface{}{
						"type":        "string",
						"description": "Recipient email address",
					},
					"subject": map[string]interface{}{
						"type":        "string",
						"description": "Email subject line",
					},
					"body": map[string]interface{}{
						"type":        "string",
						"description": "Email body content",
					},
				},
				"required": []string{"to", "subject", "body"},
			},
		},
		{
			Name:        "note_add",
			Description: "Add a note to the family notes. Use this when the user wants to save something for later - information, instructions, credentials, contacts, or any text they want to keep.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Title of the note",
					},
					"content": map[string]interface{}{
						"type":        "string",
						"description": "Content of the note",
					},
				},
				"required": []string{"title"},
			},
		},
		{
			Name:        "note_search",
			Description: "Search the family notes. Use when the user asks about previously saved notes, information, or instructions.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "note_update",
			Description: "Update an existing note. Use when the user wants to change the title or content of a saved note.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the note to update",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Updated title",
					},
					"content": map[string]interface{}{
						"type":        "string",
						"description": "Updated content",
					},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "islamqa",
			Description: "Search IslamQA for scholarly answers to Islamic questions. Returns answers from Sheikh Muhammed Salih Al-Munajjid's Q&A archive covering faith, fiqh, family, history, and more. Use this when the user asks about Islamic rulings, practices, or questions that scholars have already answered.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "The Islamic question or topic to search for",
					},
				},
				"required": []string{"query"},
			},
		},
	}
}

// ExecuteTool runs a tool and returns the result
func ExecuteTool(name string, input map[string]interface{}) (string, error) {
	switch name {
	case "fetch":
		return executeFetchURL(input)
	case "search":
		return executeRecall(input)
	case "store":
		return executeRemember(input)
	case "reminder":
		return executeIslamicSearch(input)
	case "wikipedia":
		return executeWikipedia(input)
	case "www":
		return executeWebSearch(input)
	case "email_check":
		return executeEmailCheck(input)
	case "email_send":
		return executeEmailSend(input)
	case "note_add":
		return executeNoteAdd(input)
	case "note_search":
		return executeNoteSearch(input)
	case "note_update":
		return executeNoteUpdate(input)
	case "islamqa":
		return executeIslamQA(input)
	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

func executeIslamicSearch(input map[string]interface{}) (string, error) {
	query, _ := input["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	return SearchIslam(query)
}

func executeWikipedia(input map[string]interface{}) (string, error) {
	query, _ := input["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	return WikiSearch(query)
}

func executeWebSearch(input map[string]interface{}) (string, error) {
	if isIntegrationEnabled != nil && !isIntegrationEnabled("brave_search") {
		return "", fmt.Errorf("web search is disabled")
	}
	query, _ := input["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	result, err := WebSearch(query)
	if err != nil {
		log.Printf("Web search error: %v", err)
		return "", err
	}
	log.Printf("Web search got %d chars", len(result))
	return result, nil
}

func executeFetchURL(input map[string]interface{}) (string, error) {
	url, _ := input["url"].(string)
	if url == "" {
		return "", fmt.Errorf("url is required")
	}

	// Check if we already have this URL in memory
	if store != nil {
		if existing, err := store.GetEntryByTitle("url", url); err == nil {
			content, _ := existing["Content"].(string)
			createdAt, _ := existing["CreatedAt"].(time.Time)
			return fmt.Sprintf("[From memory, fetched %s]\n\n%s", createdAt.Format("2006-01-02"), content), nil
		}
	}

	// Fetch the URL
	content, err := FetchURL(url)
	if err != nil {
		return "", err
	}

	// Save to memory
	if store != nil {
		metadata, _ := json.Marshal(map[string]interface{}{
			"url":        url,
			"fetched_at": time.Now().Format(time.RFC3339),
		})
		store.SaveEntry("url", url, content, string(metadata))
	}

	return content, nil
}

func executeRecall(input map[string]interface{}) (string, error) {
	query, _ := input["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}

	if store == nil {
		return "Memory not available", nil
	}

	results, err := store.SearchEntries(query)
	if err != nil {
		return "", err
	}

	if len(results) == 0 {
		return "No results found in memory.", nil
	}

	// Format results
	var output string
	for i, r := range results {
		title, _ := r["Title"].(string)
		typ, _ := r["Type"].(string)
		content, _ := r["Content"].(string)
		output += fmt.Sprintf("[%d] %s (%s):\n%s\n\n", i+1, title, typ, content)
	}

	return output, nil
}

func executeRemember(input map[string]interface{}) (string, error) {
	title, _ := input["title"].(string)
	content, _ := input["content"].(string)

	if title == "" || content == "" {
		return "", fmt.Errorf("title and content are required")
	}

	if store == nil {
		return "Memory not available", nil
	}

	_, err := store.SaveEntry("note", title, content, "")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("Saved to memory: %s", title), nil
}

func executeEmailCheck(input map[string]interface{}) (string, error) {
	unreadOnly, _ := input["unread_only"].(bool)
	limit := 10
	if l, ok := input["limit"].(float64); ok {
		limit = int(l)
	}

	emails, err := FetchEmails(limit, unreadOnly)
	if err != nil {
		return "", fmt.Errorf("failed to check email: %w", err)
	}

	if len(emails) == 0 {
		if unreadOnly {
			return "No unread emails.", nil
		}
		return "Inbox is empty.", nil
	}

	var output string
	for i, e := range emails {
		body := e.Body
		if len(body) > 500 {
			body = body[:500] + "..."
		}
		output += fmt.Sprintf("[%d] From: %s\nDate: %s\nSubject: %s\n\n%s\n\n---\n\n",
			i+1, e.From, e.Date.Format("2006-01-02 15:04"), e.Subject, body)
	}

	return output, nil
}

func executeEmailSend(input map[string]interface{}) (string, error) {
	to, _ := input["to"].(string)
	subject, _ := input["subject"].(string)
	body, _ := input["body"].(string)

	if to == "" || subject == "" || body == "" {
		return "", fmt.Errorf("to, subject, and body are required")
	}

	msgID, err := SendEmail(to, subject, body)
	if err != nil {
		return "", fmt.Errorf("failed to send email: %w", err)
	}

	// Notify callback to create thread mapping
	if onEmailSent != nil {
		onEmailSent(msgID, to, subject)
	}

	return fmt.Sprintf("Email sent to %s with subject: %s", to, subject), nil
}

func executeNoteAdd(input map[string]interface{}) (string, error) {
	if noteStore == nil {
		return "", fmt.Errorf("note storage not available")
	}

	title, _ := input["title"].(string)
	content, _ := input["content"].(string)

	if title == "" {
		return "", fmt.Errorf("title is required")
	}

	var userID int64
	if getCurrentUserID != nil {
		userID = getCurrentUserID()
	}

	id, err := noteStore.AddNoteItem(title, content, userID)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("Added note: '%s' (ID: %d)", title, id), nil
}

func executeNoteSearch(input map[string]interface{}) (string, error) {
	if noteStore == nil {
		return "", fmt.Errorf("note storage not available")
	}

	query, _ := input["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}

	var userID int64
	if getCurrentUserID != nil {
		userID = getCurrentUserID()
	}

	items, err := noteStore.SearchNotes(query, userID)
	if err != nil {
		return "", err
	}

	if len(items) == 0 {
		return fmt.Sprintf("No notes found matching '%s'", query), nil
	}

	var result string
	for _, item := range items {
		result += fmt.Sprintf("[%v] %s\n", item["ID"], item["Title"])
		if content, ok := item["Content"].(string); ok && content != "" {
			if len(content) > 200 {
				content = content[:200] + "..."
			}
			result += fmt.Sprintf("    %s\n", content)
		}
		result += "\n"
	}

	return result, nil
}

func executeNoteUpdate(input map[string]interface{}) (string, error) {
	if noteStore == nil {
		return "", fmt.Errorf("note storage not available")
	}

	idFloat, ok := input["id"].(float64)
	if !ok {
		return "", fmt.Errorf("id is required")
	}
	id := int64(idFloat)

	// Get existing item
	existing, err := noteStore.GetNoteItem(id)
	if err != nil {
		return "", fmt.Errorf("item not found: %w", err)
	}

	// Build updates
	updates := make(map[string]interface{})
	if v, ok := input["title"].(string); ok && v != "" {
		updates["title"] = v
	}
	if v, ok := input["content"].(string); ok {
		updates["content"] = v
	}

	if len(updates) == 0 {
		return "No updates provided", nil
	}

	err = noteStore.UpdateNoteItem(id, updates)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("Updated note: %s", existing["Title"]), nil
}

func executeIslamQA(input map[string]interface{}) (string, error) {
	query, _ := input["query"].(string)
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	if store == nil {
		return "IslamQA not available", nil
	}
	results, err := store.SearchIslamQA(query)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "No results found in IslamQA.", nil
	}
	var output string
	for i, r := range results {
		question, _ := r["Question"].(string)
		answer, _ := r["Answer"].(string)
		category, _ := r["Category"].(string)
		if len(answer) > 2000 {
			answer = answer[:2000] + "..."
		}
		output += fmt.Sprintf("[%d] Category: %s\nQ: %s\nA: %s\n\n", i+1, category, question, answer)
	}
	return output, nil
}
