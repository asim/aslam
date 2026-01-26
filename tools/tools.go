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
}

// VaultStorage interface for vault operations
type VaultStorage interface {
	AddVaultItem(category, name, description, details, credentials, notes string) (int64, error)
	SearchVault(query string) ([]map[string]interface{}, error)
	GetVaultItems(category string) ([]map[string]interface{}, error)
	GetVaultItem(id int64) (map[string]interface{}, error)
	UpdateVaultItem(id int64, updates map[string]interface{}) error
}

var store Storage
var vaultStore VaultStorage

// SetStorage sets the storage backend
func SetStorage(s Storage) {
	store = s
}

// SetVaultStorage sets the vault storage backend
func SetVaultStorage(v VaultStorage) {
	vaultStore = v
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
			Name:        "recall",
			Description: "Search your memory/knowledge base for information. Use this to recall previously fetched URLs, saved notes, or any stored knowledge. Search by keywords, URL, domain, or topic.",
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
			Name:        "remember",
			Description: "Save something to memory for later recall. Use this to store important facts, notes, or information the user wants you to remember.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Short title or key for this memory",
					},
					"content": map[string]interface{}{
						"type":        "string",
						"description": "The information to remember",
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
			Name:        "vault_add",
			Description: "Add something to keep track of - assets, accounts, people, instructions, documents. Use this when the user mentions something important they own, have access to, or need to remember. Categories: asset, account, person, instruction, document.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"category": map[string]interface{}{
						"type":        "string",
						"description": "Category: asset, account, person, instruction, document",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Name or title of the item",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Brief description",
					},
					"details": map[string]interface{}{
						"type":        "string",
						"description": "Additional details, instructions, or context",
					},
					"credentials": map[string]interface{}{
						"type":        "string",
						"description": "Login info, account numbers, or access credentials if applicable",
					},
					"notes": map[string]interface{}{
						"type":        "string",
						"description": "Any other notes",
					},
				},
				"required": []string{"category", "name"},
			},
		},
		{
			Name:        "vault_search",
			Description: "Search for things being tracked - assets, accounts, people, instructions, documents. Use this when the user asks about what they have, own, or need to do.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query",
					},
					"category": map[string]interface{}{
						"type":        "string",
						"description": "Filter by category (optional): asset, account, person, instruction, document",
					},
				},
			},
		},
		{
			Name:        "vault_update",
			Description: "Update an existing vault item. Use this when the user wants to change or add information to something already being tracked.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "integer",
						"description": "ID of the item to update",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Updated name",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "Updated description",
					},
					"details": map[string]interface{}{
						"type":        "string",
						"description": "Updated details",
					},
					"credentials": map[string]interface{}{
						"type":        "string",
						"description": "Updated credentials",
					},
					"notes": map[string]interface{}{
						"type":        "string",
						"description": "Updated notes",
					},
					"status": map[string]interface{}{
						"type":        "string",
						"description": "Status: active, closed, archived",
					},
				},
				"required": []string{"id"},
			},
		},
	}
}

// ExecuteTool runs a tool and returns the result
func ExecuteTool(name string, input map[string]interface{}) (string, error) {
	switch name {
	case "fetch":
		return executeFetchURL(input)
	case "recall":
		return executeRecall(input)
	case "remember":
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
	case "vault_add":
		return executeVaultAdd(input)
	case "vault_search":
		return executeVaultSearch(input)
	case "vault_update":
		return executeVaultUpdate(input)
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

func executeVaultAdd(input map[string]interface{}) (string, error) {
	if vaultStore == nil {
		return "", fmt.Errorf("vault storage not available")
	}
	
	category, _ := input["category"].(string)
	name, _ := input["name"].(string)
	description, _ := input["description"].(string)
	details, _ := input["details"].(string)
	credentials, _ := input["credentials"].(string)
	notes, _ := input["notes"].(string)
	
	if category == "" || name == "" {
		return "", fmt.Errorf("category and name are required")
	}
	
	id, err := vaultStore.AddVaultItem(category, name, description, details, credentials, notes)
	if err != nil {
		return "", err
	}
	
	return fmt.Sprintf("Added to vault: %s '%s' (ID: %d)", category, name, id), nil
}

func executeVaultSearch(input map[string]interface{}) (string, error) {
	if vaultStore == nil {
		return "", fmt.Errorf("vault storage not available")
	}
	
	query, _ := input["query"].(string)
	category, _ := input["category"].(string)
	
	var items []map[string]interface{}
	var err error
	
	if query != "" {
		items, err = vaultStore.SearchVault(query)
	} else {
		items, err = vaultStore.GetVaultItems(category)
	}
	
	if err != nil {
		return "", err
	}
	
	if len(items) == 0 {
		if query != "" {
			return fmt.Sprintf("No items found matching '%s'", query), nil
		}
		if category != "" {
			return fmt.Sprintf("No items in category '%s'", category), nil
		}
		return "Vault is empty.", nil
	}
	
	var result string
	for _, item := range items {
		result += fmt.Sprintf("[%v] %s: %s\n", item["ID"], item["Category"], item["Name"])
		if desc, ok := item["Description"].(string); ok && desc != "" {
			result += fmt.Sprintf("    %s\n", desc)
		}
		if details, ok := item["Details"].(string); ok && details != "" {
			result += fmt.Sprintf("    Details: %s\n", details)
		}
		if notes, ok := item["Notes"].(string); ok && notes != "" {
			result += fmt.Sprintf("    Notes: %s\n", notes)
		}
		result += "\n"
	}
	
	return result, nil
}

func executeVaultUpdate(input map[string]interface{}) (string, error) {
	if vaultStore == nil {
		return "", fmt.Errorf("vault storage not available")
	}
	
	idFloat, ok := input["id"].(float64)
	if !ok {
		return "", fmt.Errorf("id is required")
	}
	id := int64(idFloat)
	
	// Get existing item
	existing, err := vaultStore.GetVaultItem(id)
	if err != nil {
		return "", fmt.Errorf("item not found: %w", err)
	}
	
	// Build updates
	updates := make(map[string]interface{})
	for _, field := range []string{"name", "description", "details", "credentials", "notes", "status"} {
		if v, ok := input[field].(string); ok && v != "" {
			updates[field] = v
		}
	}
	
	if len(updates) == 0 {
		return "No updates provided", nil
	}
	
	err = vaultStore.UpdateVaultItem(id, updates)
	if err != nil {
		return "", err
	}
	
	return fmt.Sprintf("Updated vault item: %s", existing["Name"]), nil
}
