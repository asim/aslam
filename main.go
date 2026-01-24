package main

import (
	"bytes"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

//go:embed templates/*
var templates embed.FS

var (
	db        *sql.DB
	tmpl      *template.Template
	anthropicKey string
	anthropicModel string
)

func main() {
	// Load config
	loadEnv()
	
	anthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	anthropicModel = os.Getenv("ANTHROPIC_MODEL")
	if anthropicModel == "" {
		anthropicModel = "claude-3-haiku-20240307"
	}
	
	dbKey := os.Getenv("ASLAM_KEY")
	if dbKey == "" {
		// Try loading from key file
		keyPath := filepath.Join(os.Getenv("HOME"), ".aslam", ".key")
		if data, err := os.ReadFile(keyPath); err == nil {
			dbKey = strings.TrimSpace(string(data))
		}
	}
	if dbKey == "" {
		log.Fatal("ASLAM_KEY not set and ~/.aslam/.key not found")
	}

	// Open encrypted database
	dbPath := os.Getenv("ASLAM_DB")
	if dbPath == "" {
		dbPath = filepath.Join(os.Getenv("HOME"), ".aslam", "aslam.db")
	}
	
	var err error
	// go-sqlcipher uses _pragma_key - need to URL encode the key
	encodedKey := url.QueryEscape(dbKey)
	dsn := fmt.Sprintf("%s?_pragma_key=%s&_pragma_cipher_page_size=4096", dbPath, encodedKey)
	db, err = sql.Open("sqlite3", dsn)
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}
	defer db.Close()
	
	// Run migrations
	if err := migrate(); err != nil {
		log.Fatal("Migration failed:", err)
	}

	// Parse templates
	funcs := template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04")
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
	}
	
	tmpl = template.Must(template.New("").Funcs(funcs).ParseFS(templates, "templates/*.html"))

	// Routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/chat", handleChat)
	http.HandleFunc("/chat/", handleChatView)
	http.HandleFunc("/chat/new", handleNewChat)
	http.HandleFunc("/chat/send", handleSendMessage)
	http.HandleFunc("/search", handleSearch)
	http.HandleFunc("/entries", handleEntries)
	http.HandleFunc("/entries/", handleEntryView)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	
	log.Printf("Aslam running on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func loadEnv() {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			os.Setenv(parts[0], parts[1])
		}
	}
}

func migrate() error {
	// Conversations table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS conversations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT,
			summary TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	
	// Messages table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id INTEGER NOT NULL,
			role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
			content TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return err
	}
	
	// FTS for messages
	_, err = db.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts4(
			content,
			content='messages'
		)
	`)
	if err != nil {
		return err
	}
	
	// Trigger for FTS
	db.Exec(`CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
		INSERT INTO messages_fts(docid, content) VALUES (new.id, new.content);
	END`)
	
	db.Exec(`CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
		DELETE FROM messages_fts WHERE docid = old.id;
	END`)
	
	// Index
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id)`)
	
	return nil
}

// Handlers

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	// Get recent conversations
	convs, _ := getRecentConversations(10)
	
	if err := tmpl.ExecuteTemplate(w, "home.html", map[string]interface{}{
		"Conversations": convs,
	}); err != nil {
		log.Printf("Template error: %v", err)
	}
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	convs, _ := getRecentConversations(50)
	tmpl.ExecuteTemplate(w, "chat_list.html", map[string]interface{}{
		"Conversations": convs,
	})
}

func handleChatView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/chat/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	conv, err := getConversation(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	messages, _ := getMessages(id)
	
	tmpl.ExecuteTemplate(w, "chat.html", map[string]interface{}{
		"Conversation": conv,
		"Messages":     messages,
	})
}

func handleNewChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	
	id, err := createConversation("New conversation")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	http.Redirect(w, r, fmt.Sprintf("/chat/%d", id), http.StatusSeeOther)
}

func handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	
	convID, _ := strconv.ParseInt(r.FormValue("conversation_id"), 10, 64)
	userMessage := strings.TrimSpace(r.FormValue("message"))
	
	if convID == 0 || userMessage == "" {
		http.Error(w, "Missing fields", 400)
		return
	}
	
	// Save user message
	if err := addMessage(convID, "user", userMessage); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	// Get conversation history for context
	messages, _ := getMessages(convID)
	
	// Generate AI response
	response, err := generateResponse(messages)
	if err != nil {
		// Save error as assistant message
		addMessage(convID, "assistant", "Error: "+err.Error())
	} else {
		addMessage(convID, "assistant", response)
	}
	
	// Update conversation title if first message
	if len(messages) <= 1 {
		title := userMessage
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		updateConversationTitle(convID, title)
	}
	
	http.Redirect(w, r, fmt.Sprintf("/chat/%d", convID), http.StatusSeeOther)
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	
	var results []map[string]interface{}
	if query != "" {
		results, _ = searchMessages(query)
	}
	
	tmpl.ExecuteTemplate(w, "search.html", map[string]interface{}{
		"Query":   query,
		"Results": results,
	})
}

func handleEntries(w http.ResponseWriter, r *http.Request) {
	entries, _ := getEntries(50)
	tmpl.ExecuteTemplate(w, "entries.html", map[string]interface{}{
		"Entries": entries,
	})
}

func handleEntryView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/entries/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	entry, err := getEntry(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	tmpl.ExecuteTemplate(w, "entry.html", entry)
}

// Database functions

type Conversation struct {
	ID        int64
	Title     string
	Summary   sql.NullString
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Message struct {
	ID             int64
	ConversationID int64
	Role           string
	Content        string
	CreatedAt      time.Time
}

func getRecentConversations(limit int) ([]Conversation, error) {
	rows, err := db.Query(`
		SELECT id, title, summary, created_at, updated_at 
		FROM conversations 
		ORDER BY updated_at DESC 
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var convs []Conversation
	for rows.Next() {
		var c Conversation
		rows.Scan(&c.ID, &c.Title, &c.Summary, &c.CreatedAt, &c.UpdatedAt)
		convs = append(convs, c)
	}
	return convs, nil
}

func getConversation(id int64) (*Conversation, error) {
	var c Conversation
	err := db.QueryRow(`
		SELECT id, title, summary, created_at, updated_at 
		FROM conversations WHERE id = ?
	`, id).Scan(&c.ID, &c.Title, &c.Summary, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func createConversation(title string) (int64, error) {
	result, err := db.Exec(`INSERT INTO conversations (title) VALUES (?)`, title)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func updateConversationTitle(id int64, title string) error {
	_, err := db.Exec(`UPDATE conversations SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, title, id)
	return err
}

func getMessages(convID int64) ([]Message, error) {
	rows, err := db.Query(`
		SELECT id, conversation_id, role, content, created_at 
		FROM messages 
		WHERE conversation_id = ? 
		ORDER BY created_at ASC
	`, convID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var msgs []Message
	for rows.Next() {
		var m Message
		rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.CreatedAt)
		msgs = append(msgs, m)
	}
	return msgs, nil
}

func addMessage(convID int64, role, content string) error {
	_, err := db.Exec(`
		INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)
	`, convID, role, content)
	if err != nil {
		return err
	}
	// Update conversation timestamp
	db.Exec(`UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, convID)
	return nil
}

func searchMessages(query string) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT m.id, m.conversation_id, m.role, m.content, m.created_at, c.title
		FROM messages m
		JOIN messages_fts fts ON m.id = fts.docid
		JOIN conversations c ON m.conversation_id = c.id
		WHERE messages_fts MATCH ?
		ORDER BY m.created_at DESC
		LIMIT 50
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var results []map[string]interface{}
	for rows.Next() {
		var id, convID int64
		var role, content, title string
		var createdAt time.Time
		rows.Scan(&id, &convID, &role, &content, &createdAt, &title)
		results = append(results, map[string]interface{}{
			"ID":             id,
			"ConversationID": convID,
			"Role":           role,
			"Content":        content,
			"CreatedAt":      createdAt,
			"Title":          title,
		})
	}
	return results, nil
}

func getEntries(limit int) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT id, type, title, content, created_at 
		FROM entries 
		ORDER BY created_at DESC 
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var entries []map[string]interface{}
	for rows.Next() {
		var id int64
		var typ, title string
		var content sql.NullString
		var createdAt time.Time
		rows.Scan(&id, &typ, &title, &content, &createdAt)
		entries = append(entries, map[string]interface{}{
			"ID":        id,
			"Type":      typ,
			"Title":     title,
			"Content":   content.String,
			"CreatedAt": createdAt,
		})
	}
	return entries, nil
}

func getEntry(id int64) (map[string]interface{}, error) {
	var typ, title string
	var content, metadata sql.NullString
	var createdAt, updatedAt time.Time
	
	err := db.QueryRow(`
		SELECT id, type, title, content, metadata, created_at, updated_at 
		FROM entries WHERE id = ?
	`, id).Scan(&id, &typ, &title, &content, &metadata, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	
	return map[string]interface{}{
		"ID":        id,
		"Type":      typ,
		"Title":     title,
		"Content":   content.String,
		"Metadata":  metadata.String,
		"CreatedAt": createdAt,
		"UpdatedAt": updatedAt,
	}, nil
}

// AI functions

func generateResponse(messages []Message) (string, error) {
	if anthropicKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY not set")
	}
	
	// Build messages for API
	var apiMessages []map[string]string
	for _, m := range messages {
		if m.Role == "system" {
			continue
		}
		apiMessages = append(apiMessages, map[string]string{
			"role":    m.Role,
			"content": m.Content,
		})
	}
	
	systemPrompt := `You are Aslam, a personal family assistant for the Aslam family. You help with:
- Organizing thoughts and ideas
- Managing assets and accounts
- Making decisions about family matters
- Tracking projects and tasks
- Providing advice on financial, legal, and personal matters

Be concise, practical, and helpful. When discussing sensitive matters like finances or accounts, be thorough but discrete. Help structure and clarify thinking. When appropriate, suggest creating entries in the knowledge base to record important decisions or information.

You have access to a knowledge base of past conversations and entries that can be searched.`
	
	reqBody := map[string]interface{}{
		"model":      anthropicModel,
		"max_tokens": 2048,
		"system":     systemPrompt,
		"messages":   apiMessages,
	}
	
	jsonBody, _ := json.Marshal(reqBody)
	
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}
	
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	
	if len(result.Content) == 0 {
		return "", fmt.Errorf("empty response")
	}
	
	return result.Content[0].Text, nil
}
