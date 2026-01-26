package main

import (
	"bytes"
	"crypto/rand"
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
	"strconv"
	"strings"
	"time"

	"aslam/db"
	"aslam/tools"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

//go:embed html/*
var templates embed.FS

//go:embed README.md
var readmeContent string

//go:embed claude.md
var claudeContent string

var (
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

	// Initialize database
	if err := db.Init(); err != nil {
		log.Fatal("Database init failed:", err)
	}
	defer db.Close()

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
	
	tmpl = template.Must(template.New("").Funcs(funcs).ParseFS(templates, "html/*.html"))

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
	http.HandleFunc("/api/chat/stream", requireAuth(handleAPISendMessageStream))
	http.HandleFunc("/api/chat/new", requireAuth(handleAPINewChat))
	http.HandleFunc("/api/chat/delete", requireAuth(handleAPIDeleteChat))
	http.HandleFunc("/api/chats", requireAuth(handleAPIChats))
	http.HandleFunc("/api/search", requireAuth(handleAPISearch))
	http.HandleFunc("/search", requireAuth(handleSearch))
	http.HandleFunc("/entries", requireAuth(handleEntries))
	http.HandleFunc("/entries/", requireAuth(handleEntryView))
	http.HandleFunc("/dev", requireAuth(handleDev))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	
	// Set up tools storage
	tools.SetStorage(&dbStorage{})

	log.Printf("System prompt length: %d", len(systemPrompt))
	log.Printf("Aslam running on http://localhost:%s", port)

	// Start email worker
	startEmailWorker()

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

// dbStorage implements tools.Storage interface
type dbStorage struct{}

func (s *dbStorage) SaveEntry(entryType, title, content, metadata string) (int64, error) {
	return db.SaveEntry(entryType, title, content, metadata)
}

func (s *dbStorage) GetEntryByTitle(entryType, title string) (map[string]interface{}, error) {
	return db.GetEntryByTitle(entryType, title)
}

func (s *dbStorage) SearchEntries(query string) ([]map[string]interface{}, error) {
	return db.SearchEntries(query)
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

// Auth middleware and handlers

func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Redirect www to non-www
		if r.Host == "www.aslam.org" {
			http.Redirect(w, r, "https://aslam.org"+r.URL.Path, http.StatusMovedPermanently)
			return
		}

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

func getSession(r *http.Request) *db.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		log.Printf("No session cookie: %v", err)
		return nil
	}
	log.Printf("Session cookie found: %s...", cookie.Value[:min(10, len(cookie.Value))])
	session := db.GetSessionByToken(cookie.Value)
	if session == nil {
		log.Printf("Session not found in DB for token")
	} else {
		log.Printf("Session valid for: %s", session.Email)
	}
	return session
}

func createSession(email, name string) string {
	token, err := db.CreateSession(email, name)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		return ""
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
	db.CreateOAuthState(state)

	// Store state in cookie (works across www/non-www with Domain)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
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
	if !db.ValidateOAuthState(queryState) {
		log.Printf("OAuth callback: state not found in db: %s", queryState)
		http.Error(w, "Invalid or expired state. Try logging in again.", 400)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Path:   "/",
		
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
	log.Printf("Created session token: %s... (len=%d)", token[:min(10, len(token))], len(token))
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Domain:   "aslam.org",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
		Expires:  time.Now().Add(30 * 24 * time.Hour),
	})

	log.Printf("User logged in: %s (%s)", userInfo.Name, email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		db.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Path:   "/",
		Domain: "aslam.org",
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
	convs, _ := db.GetRecentConversations(10)
	
	if err := tmpl.ExecuteTemplate(w, "home.html", map[string]interface{}{
		"Conversations": convs,
	}); err != nil {
		log.Printf("Template error: %v", err)
	}
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	convs, _ := db.GetRecentConversations(50)
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
	
	conv, err := db.GetConversation(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	messages, _ := db.GetMessages(id)
	
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
	
	id, err := db.CreateConversation("New conversation")
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
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	// Get conversation history for context
	messages, _ := db.GetMessages(convID)
	
	// Generate AI response
	response, err := generateResponse(messages)
	if err != nil {
		// Save error as assistant message
		db.AddMessage(convID, "assistant", "Error: "+err.Error())
	} else {
		db.AddMessage(convID, "assistant", response)
	}
	
	// Update conversation title if first message
	if len(messages) <= 1 {
		title := userMessage
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		db.UpdateConversationTitle(convID, title)
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
	if err := db.AddMessage(req.ConversationID, "user", req.Message); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	// Get conversation history for context
	messages, _ := db.GetMessages(req.ConversationID)

	// Generate AI response
	response, err := generateResponse(messages)
	if err != nil {
		response = "Error: " + err.Error()
	}
	db.AddMessage(req.ConversationID, "assistant", response)

	// Update conversation title if first message
	if len(messages) <= 1 {
		title := req.Message
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		db.UpdateConversationTitle(req.ConversationID, title)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"response": response})
}

func handleAPINewChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	id, err := db.CreateConversation("New conversation")
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

	// Delete conversation (messages deleted by cascade)
	if err := db.DeleteConversation(req.ID); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAPIChats(w http.ResponseWriter, r *http.Request) {
	convs, err := db.GetRecentConversations(50)
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

	results, err := db.SearchMessages(query)
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
		results, _ = db.SearchMessages(query)
	}
	
	tmpl.ExecuteTemplate(w, "search.html", map[string]interface{}{
		"Query":   query,
		"Results": results,
	})
}

func handleEntries(w http.ResponseWriter, r *http.Request) {
	entries, _ := db.GetEntries(50)
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
	
	entry, err := db.GetEntry(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	tmpl.ExecuteTemplate(w, "entry.html", entry)
}

// Database functions


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

func generateResponse(messages []db.Message) (string, error) {
	return generateResponseWithProgress(messages, nil)
}

func generateResponseWithProgress(messages []db.Message, onTool func(string)) (string, error) {
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
					if onTool != nil {
						onTool(block.Name)
					}
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

func handleAPISendMessageStream(w http.ResponseWriter, r *http.Request) {
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

	// Set up SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", 500)
		return
	}

	sendEvent := func(event, data string) {
		fmt.Fprintf(w, "event: %s\n", event)
		// SSE requires each line of data to have data: prefix
		for _, line := range strings.Split(data, "\n") {
			fmt.Fprintf(w, "data: %s\n", line)
		}
		fmt.Fprintf(w, "\n")
		flusher.Flush()
	}

	// Save user message
	if err := db.AddMessage(req.ConversationID, "user", req.Message); err != nil {
		sendEvent("error", err.Error())
		return
	}

	// Get conversation history for context
	messages, _ := db.GetMessages(req.ConversationID)

	// Generate AI response with progress callback
	response, err := generateResponseWithProgress(messages, func(toolName string) {
		log.Printf("Sending tool event: %s", toolName)
		sendEvent("tool", toolName)
	})
	if err != nil {
		response = "Error: " + err.Error()
	}
	db.AddMessage(req.ConversationID, "assistant", response)

	// Update conversation title if first message
	if len(messages) <= 1 {
		title := req.Message
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		db.UpdateConversationTitle(req.ConversationID, title)
	}

	sendEvent("done", response)
}

func handleDev(w http.ResponseWriter, r *http.Request) {
	toolDefs := tools.GetTools()
	
	// Build integrations status
	integrations := []map[string]interface{}{
		{
			"Name":        "Anthropic Claude",
			"Description": "AI model for chat responses",
			"Enabled":     anthropicKey != "",
			"Details":     anthropicModel,
		},
		{
			"Name":        "Google OAuth",
			"Description": "User authentication",
			"Enabled":     googleClientID != "" && googleClientSecret != "",
			"Details":     googleRedirectURI,
		},
		{
			"Name":        "Brave Search",
			"Description": "Web search via www tool",
			"Enabled":     os.Getenv("BRAVE_API_KEY") != "",
			"Details":     "2000 free queries/month",
		},
		{
			"Name":        "Gmail",
			"Description": "Email via IMAP/SMTP",
			"Enabled":     os.Getenv("GMAIL_USER") != "" && os.Getenv("GMAIL_APP_PASSWORD") != "",
			"Details":     os.Getenv("GMAIL_USER"),
		},
	}
	
	tmpl.ExecuteTemplate(w, "dev.html", map[string]interface{}{
		"Model":        anthropicModel,
		"Tools":        toolDefs,
		"Integrations": integrations,
	})
}
