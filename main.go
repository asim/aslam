package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
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

	"aslam/tools"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

//go:embed templates/*
var templates embed.FS

//go:embed README.md
var readmeContent string

//go:embed claude.md
var claudeContent string

var (
	db             *sql.DB
	tmpl           *template.Template
	anthropicKey   string
	anthropicModel string

	// OAuth config
	googleClientID     string
	googleClientSecret string
	googleRedirectURI  string
	allowedEmails      map[string]bool
	sessionSecret      []byte
	devToken           string
	apiKey             string
)

type Session struct {
	Token     string
	Email     string
	Name      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func main() {
	// Load config
	loadEnv()

	anthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	anthropicModel = os.Getenv("ANTHROPIC_MODEL")
	if anthropicModel == "" {
		anthropicModel = "claude-3-haiku-20240307"
	}

	// OAuth config
	googleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	googleRedirectURI = os.Getenv("GOOGLE_REDIRECT_URI")
	if googleRedirectURI == "" {
		googleRedirectURI = "http://localhost:8000/auth/callback"
	}

	// Parse allowed emails
	allowedEmails = make(map[string]bool)
	for _, email := range strings.Split(os.Getenv("ALLOWED_EMAILS"), ",") {
		email = strings.TrimSpace(strings.ToLower(email))
		if email != "" {
			allowedEmails[email] = true
		}
	}

	// Session secret
	sessionSecret = []byte(os.Getenv("SESSION_SECRET"))
	if len(sessionSecret) == 0 {
		sessionSecret = make([]byte, 32)
		rand.Read(sessionSecret)
		log.Println("Warning: SESSION_SECRET not set, using random (sessions won't persist across restarts)")
	}

	// Dev token for testing
	devToken = os.Getenv("DEV_TOKEN")
	apiKey = os.Getenv("API_KEY")

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

	// Auth routes (no auth required)
	http.HandleFunc("/auth/login", handleLogin)
	http.HandleFunc("/auth/callback", handleOAuthCallback)
	http.HandleFunc("/auth/logout", handleLogout)

	// Protected routes
	http.HandleFunc("/", requireAuth(handleHome))
	http.HandleFunc("/chat", requireAuth(handleChat))
	http.HandleFunc("/chat/", requireAuth(handleChatView))
	http.HandleFunc("/chat/new", requireAuth(handleNewChat))
	http.HandleFunc("/chat/send", requireAuth(handleSendMessage))
	http.HandleFunc("/api/chat/send", requireAuth(handleAPISendMessage))
	http.HandleFunc("/api/chat/new", requireAuth(handleAPINewChat))
	http.HandleFunc("/api/chat/delete", requireAuth(handleAPIDeleteChat))
	http.HandleFunc("/api/chats", requireAuth(handleAPIChats))
	http.HandleFunc("/api/search", requireAuth(handleAPISearch))
	http.HandleFunc("/search", requireAuth(handleSearch))
	http.HandleFunc("/entries", requireAuth(handleEntries))
	http.HandleFunc("/entries/", requireAuth(handleEntryView))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	
	// Set up tools storage
	tools.SetStorage(&dbStorage{})

	log.Printf("System prompt length: %d", len(systemPrompt))
	log.Printf("Aslam running on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// dbStorage implements tools.Storage interface
type dbStorage struct{}

func (s *dbStorage) SaveEntry(entryType, title, content, metadata string) (int64, error) {
	return saveEntry(entryType, title, content, metadata)
}

func (s *dbStorage) GetEntryByTitle(entryType, title string) (map[string]interface{}, error) {
	return getEntryByTitle(entryType, title)
}

func (s *dbStorage) SearchEntries(query string) ([]map[string]interface{}, error) {
	return searchEntries(query)
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

	// Sessions table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			name TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// OAuth states table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS oauth_states (
			state TEXT PRIMARY KEY,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL
		)
	`)
	if err != nil {
		return err
	}

	// Clean up expired sessions and states
	db.Exec(`DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP`)
	db.Exec(`DELETE FROM oauth_states WHERE expires_at < CURRENT_TIMESTAMP`)

	// Entries table (knowledge base)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			title TEXT NOT NULL,
			content TEXT,
			metadata TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}

	// FTS for entries
	db.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS entries_fts USING fts4(
			title,
			content,
			content='entries'
		)
	`)

	db.Exec(`CREATE TRIGGER IF NOT EXISTS entries_ai AFTER INSERT ON entries BEGIN
		INSERT INTO entries_fts(docid, title, content) VALUES (new.id, new.title, new.content);
	END`)

	db.Exec(`CREATE TRIGGER IF NOT EXISTS entries_ad AFTER DELETE ON entries BEGIN
		DELETE FROM entries_fts WHERE docid = old.id;
	END`)

	db.Exec(`CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(type)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_entries_title ON entries(title)`)

	return nil
}

// Auth middleware and handlers

func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if auth is configured
		if googleClientID == "" {
			// No auth configured, allow all
			handler(w, r)
			return
		}

		// Check API key (header)
		if apiKey != "" && r.Header.Get("X-API-Key") == apiKey {
			handler(w, r)
			return
		}

		// Check dev token (query param or header)
		if devToken != "" {
			if r.URL.Query().Get("dev") == devToken || r.Header.Get("X-Dev-Token") == devToken {
				handler(w, r)
				return
			}
		}

		session := getSession(r)
		if session == nil {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
}

func getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	var s Session
	err = db.QueryRow(`
		SELECT token, email, name, created_at, expires_at 
		FROM sessions WHERE token = ? AND expires_at > CURRENT_TIMESTAMP
	`, cookie.Value).Scan(&s.Token, &s.Email, &s.Name, &s.CreatedAt, &s.ExpiresAt)
	if err != nil {
		return nil
	}
	return &s
}

func createSession(email, name string) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)

	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	_, err := db.Exec(`
		INSERT INTO sessions (token, email, name, expires_at) VALUES (?, ?, ?, ?)
	`, token, email, name, expiresAt)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
	}

	return token
}

func isHTTPS(r *http.Request) bool {
	// Check X-Forwarded-Proto for reverse proxy setups
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}
	return r.TLS != nil
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if googleClientID == "" {
		http.Error(w, "OAuth not configured", 500)
		return
	}

	// Generate state for CSRF protection
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	// Store state in database (persists across restarts)
	expiresAt := time.Now().Add(5 * time.Minute)
	db.Exec(`INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)`, state, expiresAt)

	// Store state in cookie (works across www/non-www with Domain)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		Domain:   ".aslam.org",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
	})

	// Redirect to Google OAuth
	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email%%20profile&state=%s",
		url.QueryEscape(googleClientID),
		url.QueryEscape(googleRedirectURI),
		url.QueryEscape(state),
	)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	queryState := r.URL.Query().Get("state")
	
	// Verify state exists in database (survives restarts)
	var dbState string
	err := db.QueryRow(`
		SELECT state FROM oauth_states 
		WHERE state = ? AND expires_at > CURRENT_TIMESTAMP
	`, queryState).Scan(&dbState)
	if err != nil {
		log.Printf("OAuth callback: state not found in db: %s", queryState)
		http.Error(w, "Invalid or expired state. Try logging in again.", 400)
		return
	}
	
	// Delete used state
	db.Exec(`DELETE FROM oauth_states WHERE state = ?`, queryState)

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Path:   "/",
		Domain: ".aslam.org",
		MaxAge: -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", 400)
		return
	}

	// Exchange code for token
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {googleClientID},
		"client_secret": {googleClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {googleRedirectURI},
	})
	if err != nil {
		http.Error(w, "Token exchange failed", 500)
		return
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Failed to parse token", 500)
		return
	}

	// Get user info
	userReq, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userResp, err := http.DefaultClient.Do(userReq)
	if err != nil {
		http.Error(w, "Failed to get user info", 500)
		return
	}
	defer userResp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to parse user info", 500)
		return
	}

	// Check if email is allowed
	email := strings.ToLower(userInfo.Email)
	if len(allowedEmails) > 0 && !allowedEmails[email] {
		log.Printf("Unauthorized login attempt: %s", email)
		http.Error(w, "Unauthorized: your email is not allowed", 403)
		return
	}

	// Create session
	token := createSession(email, userInfo.Name)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Domain:   ".aslam.org",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

	log.Printf("User logged in: %s (%s)", userInfo.Name, email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		db.Exec(`DELETE FROM sessions WHERE token = ?`, cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Path:   "/",
		Domain: ".aslam.org",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
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
	
	// Get user's first name from session
	userName := "You"
	if session := getSession(r); session != nil {
		parts := strings.Fields(session.Name)
		if len(parts) > 0 {
			userName = parts[0]
		}
	}
	
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	tmpl.ExecuteTemplate(w, "chat.html", map[string]interface{}{
		"Conversation": conv,
		"Messages":     messages,
		"UserName":     userName,
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

func handleAPISendMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ConversationID int64  `json:"conversation_id"`
		Message        string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	if req.ConversationID == 0 || req.Message == "" {
		jsonError(w, "Missing fields", 400)
		return
	}

	// Save user message
	if err := addMessage(req.ConversationID, "user", req.Message); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	// Get conversation history for context
	messages, _ := getMessages(req.ConversationID)

	// Generate AI response
	response, err := generateResponse(messages)
	if err != nil {
		response = "Error: " + err.Error()
	}
	addMessage(req.ConversationID, "assistant", response)

	// Update conversation title if first message
	if len(messages) <= 1 {
		title := req.Message
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		updateConversationTitle(req.ConversationID, title)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"response": response})
}

func handleAPINewChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	id, err := createConversation("New conversation")
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"id": id})
}

func handleAPIDeleteChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	// Delete messages first, then conversation
	db.Exec(`DELETE FROM messages WHERE conversation_id = ?`, req.ID)
	_, err := db.Exec(`DELETE FROM conversations WHERE id = ?`, req.ID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAPIChats(w http.ResponseWriter, r *http.Request) {
	convs, err := getRecentConversations(50)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	type convJSON struct {
		ID        int64  `json:"id"`
		Title     string `json:"title"`
		UpdatedAt string `json:"updated_at"`
	}

	var result []convJSON
	for _, c := range convs {
		result = append(result, convJSON{
			ID:        c.ID,
			Title:     c.Title,
			UpdatedAt: c.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"conversations": result})
}

func handleAPISearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
		return
	}

	results, err := searchMessages(query)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
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

func saveEntry(entryType, title, content, metadata string) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO entries (type, title, content, metadata) VALUES (?, ?, ?, ?)
	`, entryType, title, content, metadata)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func getEntryByTitle(entryType, title string) (map[string]interface{}, error) {
	var id int64
	var content, metadata sql.NullString
	var createdAt time.Time

	err := db.QueryRow(`
		SELECT id, content, metadata, created_at FROM entries WHERE type = ? AND title = ?
	`, entryType, title).Scan(&id, &content, &metadata, &createdAt)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"ID":        id,
		"Type":      entryType,
		"Title":     title,
		"Content":   content.String,
		"Metadata":  metadata.String,
		"CreatedAt": createdAt,
	}, nil
}

func searchEntries(query string) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT e.id, e.type, e.title, e.content, e.created_at
		FROM entries e
		JOIN entries_fts fts ON e.id = fts.docid
		WHERE entries_fts MATCH ?
		ORDER BY e.created_at DESC
		LIMIT 10
	`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id int64
		var typ, title string
		var content sql.NullString
		var createdAt time.Time
		rows.Scan(&id, &typ, &title, &content, &createdAt)
		
		// Truncate content for display
		c := content.String
		if len(c) > 500 {
			c = c[:500] + "..."
		}
		
		results = append(results, map[string]interface{}{
			"ID":        id,
			"Type":      typ,
			"Title":     title,
			"Content":   c,
			"CreatedAt": createdAt,
		})
	}
	return results, nil
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

var systemPromptTemplate = `You are Aslam, a personal assistant for the Aslam family.

Be concise, practical, and direct. Answer questions efficiently without unnecessary preamble.

Context: This is a Muslim family in the UK. You don't need to mention Islam in every response - only bring it up when genuinely relevant (e.g., if asked about finance, mention halal options; if asked about food, be aware of halal requirements). For general questions like "how do I get land registry info" - just answer the question directly.

You have tools available:
- fetch_url: Fetch websites, GitHub repos, docs. Content is saved to memory.
- recall: Search your memory for previously stored info.
- remember: Save notes/facts to memory.
- islamic_search: Query Quran, Hadith, Names of Allah for authoritative answers.

Do NOT:
- Add Islamic greetings or phrases unless the user does first
- Lecture about Islamic principles unprompted
- Add religious framing to mundane practical questions
- Be preachy or moralizing

DO:
- Be helpful and direct
- Give practical, actionable answers
- Use tools to fetch real information when relevant
- Keep Islamic values in mind for relevant topics (finance, food, lifestyle choices)
- Be brief - respect the user's time

---

ABOUT YOURSELF (for when users ask about Aslam, its development, or capabilities):

%s

---

DEVELOPMENT GUIDE (for technical discussions about extending Aslam):

%s`

var systemPrompt string

func init() {
	systemPrompt = fmt.Sprintf(systemPromptTemplate, readmeContent, claudeContent)
}

func generateResponse(messages []Message) (string, error) {
	if anthropicKey == "" {
		return "", fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	// Build messages for API
	var apiMessages []map[string]interface{}
	for _, m := range messages {
		if m.Role == "system" {
			continue
		}
		apiMessages = append(apiMessages, map[string]interface{}{
			"role":    m.Role,
			"content": m.Content,
		})
	}

	// Tool loop - keep calling until we get a final response
	for i := 0; i < 10; i++ { // Max 10 tool calls
		result, err := callAnthropic(apiMessages)
		if err != nil {
			return "", err
		}

		// Check if we need to handle tool use
		if result.StopReason == "tool_use" {
			// Add assistant message with tool use
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "assistant",
				"content": result.Content,
			})

			// Process tool calls and build tool results
			var toolResults []map[string]interface{}
			for _, block := range result.Content {
				if block.Type == "tool_use" {
					log.Printf("Tool call: %s(%v)", block.Name, block.Input)
					toolResult, err := tools.ExecuteTool(block.Name, block.Input)
					if err != nil {
						toolResult = fmt.Sprintf("Error: %v", err)
					}
					toolResults = append(toolResults, map[string]interface{}{
						"type":        "tool_result",
						"tool_use_id": block.ID,
						"content":     toolResult,
					})
				}
			}

			// Add tool results as user message
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})
			continue
		}

		// Extract text response
		for _, block := range result.Content {
			if block.Type == "text" {
				return block.Text, nil
			}
		}
		return "", fmt.Errorf("no text in response")
	}

	return "", fmt.Errorf("too many tool calls")
}

type anthropicResponse struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
}

type contentBlock struct {
	Type  string                 `json:"type"`
	Text  string                 `json:"text,omitempty"`
	ID    string                 `json:"id,omitempty"`
	Name  string                 `json:"name,omitempty"`
	Input map[string]interface{} `json:"input,omitempty"`
}

func callAnthropic(apiMessages []map[string]interface{}) (*anthropicResponse, error) {
	reqBody := map[string]interface{}{
		"model":      anthropicModel,
		"max_tokens": 4096,
		"tools":      tools.GetTools(),
		"system": systemPrompt,
		"messages": apiMessages,
	}

	jsonBody, _ := json.Marshal(reqBody)
	log.Printf("Sending to Anthropic: system prompt len=%d, messages=%d", len(systemPrompt), len(apiMessages))
	if len(systemPrompt) > 200 {
		log.Printf("System prompt starts: %s...", systemPrompt[:200])
	}

	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result anthropicResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
