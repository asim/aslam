package main

import (
	"archive/zip"
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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aslam/db"
	"aslam/tools"

	prayer "github.com/hablullah/go-prayer"
	_ "github.com/mutecomm/go-sqlcipher/v4"
	"golang.org/x/crypto/bcrypt"
)

//go:embed html/*
var templates embed.FS

//go:embed README.md
var readmeContent string

//go:embed claude.md
var claudeContent string

//go:embed islamqa.zip
var islamqaZip []byte

//go:embed ghazali.zip
var ghazaliZip []byte

//go:embed sources.zip
var sourcesZip []byte

var (
	tmpl           *template.Template
	anthropicKey   string
	anthropicModel string

	// OAuth config
	googleClientID     string
	googleClientSecret string
	googleRedirectURI  string
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
		anthropicModel = "claude-sonnet-4-6"
	}

	// OAuth config
	googleClientID = os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	googleRedirectURI = os.Getenv("GOOGLE_REDIRECT_URI")
	if googleRedirectURI == "" {
		googleRedirectURI = "http://localhost:8000/auth/callback"
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

	seedUsers()

	go func() {
		loadIslamQA()
		loadGhazali()
		loadSources()
	}()

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
	http.HandleFunc("/auth/login", handleAuthLogin)
	http.HandleFunc("/auth/signup", handleSignup)
	http.HandleFunc("/auth/callback", handleOAuthCallback)
	http.HandleFunc("/auth/logout", handleLogout)

	// PWA static files (no auth)
	http.HandleFunc("/manifest.json", handleStatic("manifest.json", "application/json"))
	http.HandleFunc("/sw.js", handleStatic("sw.js", "application/javascript"))
	http.HandleFunc("/icon-192.png", handleStatic("icon-192.png", "image/png"))
	http.HandleFunc("/icon-512.png", handleStatic("icon-512.png", "image/png"))

	// Public landing page
	http.HandleFunc("/", handleLanding)

	// Protected routes
	http.HandleFunc("/home", requireAuth(handleHome))
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
	http.HandleFunc("/islamqa/", requireAuth(handleIslamQAView))
	http.HandleFunc("/ghazali/", requireAuth(handleGhazaliView))
	http.HandleFunc("/quran/", requireAuth(handleQuranView))
	http.HandleFunc("/hadith/", requireAuth(handleHadithView))
	http.HandleFunc("/name/", requireAuth(handleNameView))
	http.HandleFunc("/admin", requireAuth(requireAdmin(handleAdmin)))
	http.HandleFunc("/admin/add-user", requireAuth(requireAdmin(handleAddUser)))
	http.HandleFunc("/admin/remove-user", requireAuth(requireAdmin(handleRemoveUser)))
	http.HandleFunc("/admin/add-account", requireAuth(requireAdmin(handleAddAccount)))
	http.HandleFunc("/admin/delete-account", requireAuth(requireAdmin(handleDeleteAccount)))
	http.HandleFunc("/admin/toggle-integration", requireAuth(requireAdmin(handleToggleIntegration)))
	http.HandleFunc("/profile", requireAuth(handleProfile))
	http.HandleFunc("/notes", requireAuth(handleNotes))
	http.HandleFunc("/notes/add", requireAuth(handleNoteAdd))
	http.HandleFunc("/notes/edit/", requireAuth(handleNoteEdit))
	http.HandleFunc("/notes/delete/", requireAuth(handleNoteDelete))
	http.HandleFunc("/api/chat/toggle-public", requireAuth(handleToggleChatPublic))
	http.HandleFunc("/api/location", requireAuth(handleUpdateLocation))
	http.HandleFunc("/api/notes/toggle-public", requireAuth(handleToggleNotePublic))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
	
	// Set up tools storage and integration checker
	tools.SetStorage(&dbStorage{})
	tools.SetNoteStorage(&noteStorage{})
	tools.SetCurrentUserIDGetter(func() int64 {
		if currentUserContext != nil && currentUserContext.Email != "" {
			return db.GetUserID(currentUserContext.Email)
		}
		return 0
	})
	tools.SetIntegrationChecker(func(name string) bool {
		switch name {
		case "brave_search":
			return os.Getenv("BRAVE_API_KEY") != "" && db.GetSetting("brave_search_enabled") != "false"
		case "gmail":
			return os.Getenv("GMAIL_USER") != "" && db.GetSetting("gmail_enabled") != "false"
		default:
			return true
		}
	})
	
	// When an email is sent from chat, create thread mapping so replies go to same conversation
	tools.SetEmailSentCallback(func(messageID, to, subject string) {
		if currentUserContext != nil && currentUserContext.ConversationID > 0 {
			// Create email thread pointing to current conversation
			db.CreateEmailThread(messageID, currentUserContext.ConversationID, messageID)
			log.Printf("Created email thread %s -> conversation %d", messageID, currentUserContext.ConversationID)
		}
	})

	tools.SetReminderCacher(func(query, answer string) {
		if err := db.InsertSearch(query, answer); err != nil {
			log.Printf("Failed to cache reminder result: %v", err)
		}
	})
	tools.SetIslamQASearcher(func(query string) ([]map[string]interface{}, error) {
		return db.SearchIslamQA(query)
	})
	tools.SetGhazaliSearcher(func(query string) ([]map[string]interface{}, error) {
		return db.SearchGhazali(query)
	})

	log.Printf("System prompt length: %d", len(systemPrompt))
	log.Printf("Aslam running on http://localhost:%s", port)

	// Start background workers
	startTaskProcessor()  // Handles pending tasks from any channel
	startEmailWorker()    // Polls inbox for new emails
	startDailyContentWorker() // Fetches daily verse/hadith/name

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

func (s *dbStorage) SearchAll(query string, userID int64) ([]map[string]interface{}, error) {
	return db.SearchAll(query, userID)
}

// noteStorage implements tools.NoteStorage interface
type noteStorage struct{}

func (v *noteStorage) AddNoteItem(title, content string, userID int64) (int64, error) {
	return db.AddNoteItem(title, content, userID)
}

func (v *noteStorage) SearchNotes(query string, userID int64) ([]map[string]interface{}, error) {
	items, err := db.SearchNotes(query, userID)
	if err != nil {
		return nil, err
	}
	return noteItemsToMaps(items), nil
}

func (v *noteStorage) GetNoteItem(id int64) (map[string]interface{}, error) {
	item, err := db.GetNoteItem(id)
	if err != nil {
		return nil, err
	}
	return noteItemToMap(item), nil
}

func (v *noteStorage) UpdateNoteItem(id int64, updates map[string]interface{}) error {
	// Get current item, apply updates
	item, err := db.GetNoteItem(id)
	if err != nil {
		return err
	}

	title := item.Title
	content := item.Content

	if val, ok := updates["title"].(string); ok && val != "" {
		title = val
	}
	if val, ok := updates["content"].(string); ok {
		content = val
	}

	return db.UpdateNoteItem(id, title, content)
}

func noteItemToMap(item *db.NoteItem) map[string]interface{} {
	return map[string]interface{}{
		"ID":      item.ID,
		"Title":   item.Title,
		"Content": item.Content,
	}
}

func noteItemsToMaps(items []db.NoteItem) []map[string]interface{} {
	result := make([]map[string]interface{}, len(items))
	for i, item := range items {
		result[i] = map[string]interface{}{
			"ID":      item.ID,
			"Title":   item.Title,
			"Content": item.Content,
		}
	}
	return result
}

func renderTemplate(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = map[string]interface{}{}
	}
	session := getSession(r)
	if session != nil {
		data["IsAdmin"] = db.IsAdmin(session.Email)
	}
	tmpl.ExecuteTemplate(w, name, data)
}

func handleStatic(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := templates.ReadFile("html/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(data)
	}
}

func seedUsers() {
	if db.UserCount() > 0 {
		return
	}
	emails := os.Getenv("ADMIN_EMAILS")
	if emails == "" {
		emails = os.Getenv("ALLOWED_EMAILS")
	}
	if emails == "" {
		return
	}
	for _, email := range strings.Split(emails, ",") {
		email = strings.TrimSpace(strings.ToLower(email))
		if email != "" {
			if err := db.AddUser(email, "", "admin", "seed"); err != nil {
				log.Printf("Failed to seed user %s: %v", email, err)
			} else {
				log.Printf("Seeded admin user: %s", email)
			}
		}
	}
}

const islamqaVersion = "2"

func loadIslamQA() {
	if db.GetSetting("islamqa_version") == islamqaVersion {
		log.Printf("IslamQA v%s already loaded (%d entries)", islamqaVersion, db.IslamQACount())
		return
	}

	log.Printf("IslamQA dataset changed (want v%s), reloading...", islamqaVersion)
	db.ClearIslamQA()

	r, err := zip.NewReader(bytes.NewReader(islamqaZip), int64(len(islamqaZip)))
	if err != nil {
		log.Printf("Failed to open embedded archive.zip: %v", err)
		return
	}

	total := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			log.Printf("Failed to open %s in zip: %v", f.Name, err)
			continue
		}

		var entries []struct {
			Question string `json:"question"`
			Answer   string `json:"answer"`
			Category string `json:"category"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()

		for _, e := range entries {
			category := e.Category
			if category == "" {
				category = strings.TrimSuffix(filepath.Base(f.Name), ".json")
				category = strings.ReplaceAll(category, "-", " ")
			}
			if err := db.InsertIslamQA(category, e.Question, e.Answer); err != nil {
				log.Printf("Failed to insert IslamQA entry: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("islamqa_version", islamqaVersion)
	log.Printf("Loaded %d IslamQA entries (v%s)", total, islamqaVersion)
}

// loadEnv reads key=value pairs from a .env file in the working directory and
// sets them as process environment variables (without overwriting any that are
// already set). It tolerates `export KEY=value`, surrounding quotes, and
// `# comments`, so a file that also works when `source`d in a shell is fine.
const ghazaliVersion = "1"

func loadGhazali() {
	if db.GetSetting("ghazali_version") == ghazaliVersion {
		log.Printf("Ghazali v%s already loaded (%d sections)", ghazaliVersion, db.GhazaliCount())
		return
	}

	log.Printf("Loading Ghazali dataset v%s...", ghazaliVersion)
	db.ClearGhazali()

	r, err := zip.NewReader(bytes.NewReader(ghazaliZip), int64(len(ghazaliZip)))
	if err != nil {
		log.Printf("Failed to open ghazali.zip: %v", err)
		return
	}

	total := 0
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var entries []struct {
			Volume      int    `json:"volume"`
			VolumeTitle string `json:"volume_title"`
			Chapter     string `json:"chapter"`
			Part        int    `json:"part"`
			Content     string `json:"content"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode ghazali.json: %v", err)
			continue
		}
		rc.Close()
		for _, e := range entries {
			if err := db.InsertGhazali(e.Volume, e.VolumeTitle, e.Chapter, e.Part, e.Content); err != nil {
				log.Printf("Failed to insert Ghazali section: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("ghazali_version", ghazaliVersion)
	log.Printf("Loaded %d Ghazali sections (v%s)", total, ghazaliVersion)
}

const sourcesVersion = "4"

func loadSources() {
	if db.GetSetting("sources_version") == sourcesVersion {
		log.Printf("Sources v%s already loaded (quran=%d, hadith=%d, names=%d)",
			sourcesVersion, db.QuranCount(), db.HadithCount(), db.NamesCount())
		return
	}

	log.Printf("Loading sources v%s...", sourcesVersion)
	db.ClearQuran()
	db.ClearHadith()
	db.ClearNames()

	r, err := zip.NewReader(bytes.NewReader(sourcesZip), int64(len(sourcesZip)))
	if err != nil {
		log.Printf("Failed to open sources.zip: %v", err)
		return
	}

	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			log.Printf("Failed to open %s in sources.zip: %v", f.Name, err)
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			log.Printf("Failed to read %s: %v", f.Name, err)
			continue
		}

		base := filepath.Base(f.Name)
		switch base {
		case "quran.json":
			var quranData struct {
				Chapters []struct {
					Name   string `json:"name"`
					Number int    `json:"number"`
					Verses []struct {
						Chapter  int    `json:"chapter"`
						Number   int    `json:"number"`
						Text     string `json:"text"`
						Arabic   string `json:"arabic"`
						Comments string `json:"comments"`
					} `json:"verses"`
				} `json:"chapters"`
			}
			if err := json.Unmarshal(data, &quranData); err != nil {
				log.Printf("Failed to parse quran.json: %v", err)
				continue
			}
			total := 0
			for _, ch := range quranData.Chapters {
				for _, v := range ch.Verses {
					if err := db.InsertQuranVerse(ch.Number, ch.Name, v.Number, v.Text, v.Arabic, v.Comments); err != nil {
						log.Printf("Failed to insert quran verse %d:%d: %v", ch.Number, v.Number, err)
					} else {
						total++
					}
				}
			}
			log.Printf("Loaded %d Quran verses", total)

		case "hadith.json":
			var hadithData struct {
				Name  string `json:"name"`
				Books []struct {
					Name    string `json:"name"`
					Hadiths []struct {
						Number   int    `json:"number"`
						Narrator string `json:"narrator"`
						English  string `json:"english"`
						Arabic   string `json:"arabic"`
					} `json:"hadiths"`
				} `json:"books"`
			}
			if err := json.Unmarshal(data, &hadithData); err != nil {
				log.Printf("Failed to parse hadith.json: %v", err)
				continue
			}
			total := 0
			for _, book := range hadithData.Books {
				for _, h := range book.Hadiths {
					if err := db.InsertHadith(book.Name, h.Number, h.Narrator, h.English, h.Arabic); err != nil {
						log.Printf("Failed to insert hadith %d: %v", h.Number, err)
					} else {
						total++
					}
				}
			}
			log.Printf("Loaded %d hadiths", total)

		case "names.json":
			var names []struct {
				Number      int    `json:"number"`
				English     string `json:"english"`
				Arabic      string `json:"arabic"`
				Meaning     string `json:"meaning"`
				Description string `json:"description"`
				Summary     string `json:"summary"`
			}
			if err := json.Unmarshal(data, &names); err != nil {
				log.Printf("Failed to parse names.json: %v", err)
				continue
			}
			total := 0
			for _, n := range names {
				if err := db.InsertName(n.Number, n.English, n.Arabic, n.Meaning, n.Description, n.Summary); err != nil {
					log.Printf("Failed to insert name %d: %v", n.Number, err)
				} else {
					total++
				}
			}
			log.Printf("Loaded %d Names of Allah", total)
		}
	}

	// Rebuild FTS indexes to ensure they're populated
	db.RebuildSourcesFTS()

	db.SetSetting("sources_version", sourcesVersion)
	log.Printf("Sources v%s loaded", sourcesVersion)
}

func handleQuranView(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/quran/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	chapter, err := strconv.Atoi(parts[0])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	verse, err := strconv.Atoi(parts[1])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetQuranVerse(chapter, verse)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	renderTemplate(w, r, "quran.html", item)
}

func handleHadithView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/hadith/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetHadith(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	renderTemplate(w, r, "hadith.html", item)
}

func handleNameView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/name/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetName(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	renderTemplate(w, r, "name.html", item)
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
		line = strings.TrimPrefix(line, "export ")
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Strip matching surrounding quotes.
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
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
		if !db.IsUser(session.Email) {
			http.Error(w, "Unauthorized: your email is not allowed", http.StatusForbidden)
			return
		}
		handler(w, r)
	}
}

func getSession(r *http.Request) *db.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	return db.GetSessionByToken(cookie.Value)
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

func startGoogleOAuth(w http.ResponseWriter, r *http.Request) {
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

func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	// If ?google=true, trigger Google OAuth flow
	if r.URL.Query().Get("google") == "true" {
		startGoogleOAuth(w, r)
		return
	}

	if r.Method == "POST" {
		handleLoginPost(w, r)
		return
	}

	// GET: show login page
	errMsg := r.URL.Query().Get("error")
	tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"Error":         errMsg,
		"GoogleEnabled": googleClientID != "",
	})
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")

	if email == "" || password == "" {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "Email and password are required",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	user, err := db.GetUserByEmail(email)
	if err != nil || user.PasswordHash == "" {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "Invalid email or password",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "Invalid email or password",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	// Create session
	token := createSession(email, user.Name)
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

	log.Printf("User logged in via password: %s (%s)", user.Name, email)
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		handleSignupPost(w, r)
		return
	}

	// GET: show signup page
	errMsg := r.URL.Query().Get("error")
	tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
		"Error":         errMsg,
		"GoogleEnabled": googleClientID != "",
	})
}

func handleSignupPost(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")

	// Validation
	if email == "" {
		tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
			"Error":         "Email is required",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}
	if len(password) < 8 {
		tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
			"Error":         "Password must be at least 8 characters",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	// Check if email is already taken
	if db.IsUser(email) {
		tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
			"Error":         "An account with this email already exists",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
			"Error":         "Something went wrong. Please try again.",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	// Create user
	if err := db.CreateUserWithPassword(email, name, string(hash), "user"); err != nil {
		log.Printf("Failed to create user %s: %v", email, err)
		tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
			"Error":         "Could not create account. Please try again.",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	// Create session
	token := createSession(email, name)
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

	log.Printf("New user signed up: %s (%s)", name, email)
	http.Redirect(w, r, "/home", http.StatusSeeOther)
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
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to parse user info", 500)
		return
	}

	email := strings.ToLower(userInfo.Email)

	// Auto-create user if they don't exist (open registration via Google)
	if !db.IsUser(email) {
		if err := db.AddUser(email, userInfo.Name, "user", "google"); err != nil {
			log.Printf("Failed to auto-create user %s: %v", email, err)
			http.Error(w, "Failed to create account", 500)
			return
		}
		log.Printf("Auto-created user via Google OAuth: %s (%s)", userInfo.Name, email)
	}

	// Update name and picture from Google on every login
	if userInfo.Name != "" || userInfo.Picture != "" {
		db.UpdateUserProfile(email, userInfo.Name, userInfo.Picture)
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
	http.Redirect(w, r, "/home", http.StatusSeeOther)
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

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getUserID returns the database user ID from the request session, or 0 if unauthenticated.
func getUserID(r *http.Request) int64 {
	session := getSession(r)
	if session == nil {
		return 0
	}
	return db.GetUserID(session.Email)
}

// Handlers

func handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Redirect www to non-www
	if r.Host == "www.aslam.org" {
		http.Redirect(w, r, "https://aslam.org"+r.URL.Path, http.StatusMovedPermanently)
		return
	}

	// If auth is not configured, go straight to home
	if googleClientID == "" {
		handleHome(w, r)
		return
	}

	// If user is authenticated, redirect to /home
	session := getSession(r)
	if session != nil && db.IsUser(session.Email) {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}

	// Show landing page
	tmpl.ExecuteTemplate(w, "landing.html", nil)
}

func getPrayerTimesForUser(userID int64) map[string]string {
	lat := 51.5074
	lng := -0.1278
	tzName := "Europe/London"

	if userID > 0 {
		if u, err := db.GetUserByID(userID); err == nil {
			if u.Latitude != 0 {
				lat = u.Latitude
			}
			if u.Longitude != 0 {
				lng = u.Longitude
			}
			if u.Timezone != "" {
				tzName = u.Timezone
			}
		}
	}

	if envLat := os.Getenv("LATITUDE"); envLat != "" {
		if v, err := strconv.ParseFloat(envLat, 64); err == nil && lat == 51.5074 {
			lat = v
		}
	}
	if envLng := os.Getenv("LONGITUDE"); envLng != "" {
		if v, err := strconv.ParseFloat(envLng, 64); err == nil && lng == -0.1278 {
			lng = v
		}
	}
	if envTZ := os.Getenv("TIMEZONE"); envTZ != "" && tzName == "Europe/London" {
		tzName = envTZ
	}

	tz, _ := time.LoadLocation(tzName)
	if tz == nil {
		tz = time.UTC
	}

	// Moonsighting Committee: Fajr 18°, Isha 18°
	moonsighting := &prayer.TwilightConvention{FajrAngle: 18, IshaAngle: 18}

	now := time.Now().In(tz)
	schedules, err := prayer.Calculate(prayer.Config{
		Latitude:           lat,
		Longitude:          lng,
		Timezone:           tz,
		TwilightConvention: moonsighting,
		AsrConvention:      prayer.Shafii,
		HighLatitudeAdapter: prayer.AngleBased(),
	}, now.Year())
	if err != nil {
		return nil
	}

	day := now.YearDay() - 1
	if day < 0 || day >= len(schedules) {
		return nil
	}
	s := schedules[day]

	// High latitude adjustments (UK/Europe summer)
	// Cap Fajr at no earlier than Sunrise - 90 minutes
	fajrTime := s.Fajr
	minFajr := s.Sunrise.Add(-90 * time.Minute)
	if fajrTime.Before(minFajr) {
		fajrTime = minFajr
	}

	// Cap Isha at Maghrib + 90 minutes
	ishaTime := s.Isha
	maxIsha := s.Maghrib.Add(90 * time.Minute)
	if ishaTime.After(maxIsha) {
		ishaTime = maxIsha
	}

	return map[string]string{
		"Fajr":    fajrTime.Format("15:04"),
		"Sunrise": s.Sunrise.Format("15:04"),
		"Dhuhr":   s.Zuhr.Format("15:04"),
		"Asr":     s.Asr.Format("15:04"),
		"Maghrib": s.Maghrib.Format("15:04"),
		"Isha":    ishaTime.Format("15:04"),
	}
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	convs, _ := db.GetRecentConversations(10, userID)
	dailyContent, _ := db.GetLatestReminderContent()
	randomQA, _ := db.GetRandomIslamQA()

	hasLocation := false
	if userID > 0 {
		if u, err := db.GetUserByID(userID); err == nil {
			hasLocation = u.Latitude != 0 || u.Longitude != 0
		}
	}

	renderTemplate(w, r, "home.html", map[string]interface{}{
		"Conversations": convs,
		"DailyContent":  dailyContent,
		"RandomQA":      randomQA,
		"PrayerTimes":   getPrayerTimesForUser(userID),
		"HasLocation":   hasLocation,
	})
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	convs, _ := db.GetRecentConversations(50, userID)
	renderTemplate(w, r, "chat_list.html", map[string]interface{}{
		"Conversations": convs,
		"CurrentUserID": userID,
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

	userID := getUserID(r)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}

	// Access check: owner, public, legacy (no owner), or admin
	isOwner := conv.UserID == userID || conv.UserID == 0
	if !isOwner && !conv.Public && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
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
	renderTemplate(w, r, "chat.html", map[string]interface{}{
		"Conversation": conv,
		"Messages":     messages,
		"UserName":     userName,
		"IsOwner":      isOwner || isAdmin,
	})
}

func handleNewChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userID := getUserID(r)
	id, err := db.CreateConversation("New conversation", userID)
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
	
	// Set user context
	session := getSession(r)
	if session != nil {
		currentUserContext = &UserContext{Email: session.Email, Name: session.Name, ConversationID: convID}
	}

	// Save user message
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	// Get conversation history for context
	messages, _ := db.GetMessages(convID)
	
	// Generate AI response
	response, toolsUsed, err := generateResponse(messages)
	if err != nil {
		// Save error as assistant message
		db.AddMessage(convID, "assistant", "Error: "+err.Error())
	} else {
		// Append sources if tools were used
		fullResponse := formatResponseWithSources(response, toolsUsed)
		db.AddMessage(convID, "assistant", fullResponse)
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

	// Set user context
	session := getSession(r)
	if session != nil {
		currentUserContext = &UserContext{Email: session.Email, Name: session.Name, ConversationID: req.ConversationID}
	}

	// Save user message
	if err := db.AddMessage(req.ConversationID, "user", req.Message); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	// Get conversation history for context
	messages, _ := db.GetMessages(req.ConversationID)

	// Generate AI response
	response, toolsUsed, err := generateResponse(messages)
	if err != nil {
		response = "Error: " + err.Error()
	} else {
		response = formatResponseWithSources(response, toolsUsed)
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

	userID := getUserID(r)
	id, err := db.CreateConversation("New conversation", userID)
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

	// Verify ownership: owner, legacy (no owner), or admin
	userID := getUserID(r)
	ownerID := db.GetConversationOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	if ownerID != 0 && ownerID != userID && !isAdmin {
		jsonError(w, "Access denied", 403)
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
	userID := getUserID(r)
	convs, err := db.GetRecentConversations(50, userID)
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

	// Unified search across chats, entries, and notes.
	userID := getUserID(r)
	results, err := db.SearchAll(query, userID)
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
		userID := getUserID(r)
		results, _ = db.SearchAll(query, userID)
	}

	renderTemplate(w, r, "search.html", map[string]interface{}{
		"Query":   query,
		"Results": results,
	})
}

func handleEntries(w http.ResponseWriter, r *http.Request) {
	entries, _ := db.GetEntries(50)
	renderTemplate(w, r, "entries.html", map[string]interface{}{
		"Entries": entries,
	})
}

func handleGhazaliView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/ghazali/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetGhazali(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	renderTemplate(w, r, "ghazali.html", item)
}

func handleIslamQAView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/islamqa/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetIslamQA(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	renderTemplate(w, r, "islamqa.html", item)
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
	
	renderTemplate(w, r, "entry.html", entry)
}

// Database functions


// AI functions

var systemPromptTemplate = `You are Aslam, a personal assistant for the family.

Be concise, practical, and direct. Answer questions efficiently without unnecessary preamble.

Context: This is a Muslim family in the UK. You don't need to mention Islam in every response - only bring it up when genuinely relevant (e.g., if asked about finance, mention halal options; if asked about food, be aware of halal requirements). For general questions like "how do I get land registry info" - just answer the question directly.

You are BOTH an assistant and the keeper of the family's knowledge base. Every conversation is automatically saved and indexed, so the user can search their past questions and your answers later from /search. But you also have tools to deliberately capture important things so they become first-class, searchable entries:

- note_add: When the user shares a fact worth keeping (a decision, a name, an address, a preference, a process), save it as a note.
- note_add: When the user shares something worth keeping as a note - accounts, credentials, contacts, instructions, or any text they want to save - put it in notes with a title and content.
- fetch: When you pull a URL, it is automatically cached, so the user can search it later.
- search: Before saying "I don't know", check the knowledge base first — the user may already have told you.

You have tools available:
- fetch: Fetch websites, GitHub repos, docs. Content is saved to memory.
- search: Search the knowledge base (chats, notes, IslamQA, reminder results).
- reminder: Search Islamic sources (Quran, Hadith, Names of Allah) for authoritative answers.
- wikipedia: Look up factual information.
- web_search: Search the web for current information.
- email_check: Check the assistant's inbox.
- email_send: Send an email. When the user asks you to send them an email, USE THIS TOOL to actually send it - don't just write out what the email would say. Actually call the tool.
- note_add / note_update: Save and update notes.

When asked to send information about a topic, USE the research tools first (web_search, wikipedia, reminder) to gather accurate information, then send the email with that information.

When sending emails, use this format:
- Keep it concise and informative
- Sign off with: "Best regards,\nAslam"

When responding to emails (via email reply), you're having a conversation - respond naturally like you would in chat. Don't summarize or describe what happened, just reply to what they said.

Do NOT:
- Add Islamic greetings or phrases unless the user does first
- Lecture about Islamic principles unprompted
- Add religious framing to mundane practical questions
- Be preachy or moralizing

DO:
- Be helpful and direct
- Give practical, actionable answers
- Use tools to fetch real information when relevant
- Quietly capture useful facts, credentials and references into the knowledge base so the user can find them again later
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

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func formatResponseWithSources(response string, toolsUsed []ToolUsage) string {
	if len(toolsUsed) == 0 {
		return response
	}
	
	var sources strings.Builder
	sources.WriteString("\n\n---\n**Sources:**\n")
	for _, tool := range toolsUsed {
		sources.WriteString(fmt.Sprintf("- %s: %s\n", tool.Name, tool.Input))
	}
	
	return response + sources.String()
}

// UserContext contains info about the current user for personalization
type UserContext struct {
	Email          string
	Name           string
	ConversationID int64
}

var currentUserContext *UserContext

// ToolUsage tracks a single tool call and its result
type ToolUsage struct {
	Name   string
	Input  string
	Output string
}

func generateResponse(messages []db.Message) (string, []ToolUsage, error) {
	return generateResponseWithProgress(messages, nil)
}

func generateResponseWithProgress(messages []db.Message, onTool func(string)) (string, []ToolUsage, error) {
	var toolsUsed []ToolUsage
	if anthropicKey == "" {
		return "", nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	// Build system prompt with user context
	fullSystemPrompt := systemPrompt
	if currentUserContext != nil && currentUserContext.Email != "" {
		fullSystemPrompt += fmt.Sprintf("\n\nCurrent user: %s", currentUserContext.Email)
		if currentUserContext.Name != "" {
			fullSystemPrompt += fmt.Sprintf(" (%s)", currentUserContext.Name)
		}
		fullSystemPrompt += "\nIf the user asks you to send them an email, use this address."
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
		result, err := callAnthropic(apiMessages, fullSystemPrompt)
		if err != nil {
			return "", toolsUsed, err
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
					inputJSON, _ := json.Marshal(block.Input)
					log.Printf("Tool call: %s(%v)", block.Name, block.Input)
					if onTool != nil {
						onTool(block.Name)
					}
					toolResult, err := tools.ExecuteTool(block.Name, block.Input)
					if err != nil {
						toolResult = fmt.Sprintf("Error: %v", err)
					}
					
					// Track tool usage
					toolsUsed = append(toolsUsed, ToolUsage{
						Name:   block.Name,
						Input:  string(inputJSON),
						Output: truncateString(toolResult, 500),
					})
					
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
		var textResponse string
		for _, block := range result.Content {
			if block.Type == "text" {
				textResponse = block.Text
				break
			}
		}
		
		// If no text but we had tool calls that succeeded, return a default message
		if textResponse == "" {
			return "Done.", toolsUsed, nil
		}
		return textResponse, toolsUsed, nil
	}

	return "", toolsUsed, fmt.Errorf("too many tool calls")
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

func callAnthropic(apiMessages []map[string]interface{}, sysPrompt string) (*anthropicResponse, error) {
	reqBody := map[string]interface{}{
		"model":      anthropicModel,
		"max_tokens": 4096,
		"tools":      tools.GetTools(),
		"system":     sysPrompt,
		"messages":   apiMessages,
	}

	jsonBody, _ := json.Marshal(reqBody)
	log.Printf("Sending to Anthropic: system prompt len=%d, messages=%d", len(sysPrompt), len(apiMessages))
	if len(sysPrompt) > 200 {
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

	// Set user context for this request
	session := getSession(r)
	if session != nil {
		currentUserContext = &UserContext{Email: session.Email, Name: session.Name, ConversationID: req.ConversationID}
	}

	// Save user message
	if err := db.AddMessage(req.ConversationID, "user", req.Message); err != nil {
		sendEvent("error", err.Error())
		return
	}

	// Get conversation history for context
	messages, _ := db.GetMessages(req.ConversationID)

	// Generate AI response with progress callback
	response, toolsUsed, err := generateResponseWithProgress(messages, func(toolName string) {
		log.Printf("Sending tool event: %s", toolName)
		sendEvent("tool", toolName)
	})
	if err != nil {
		// Create pending task for retry
		db.CreatePendingTask("chat", req.ConversationID, "", "")
		response = "Sorry, I encountered an error. I'll retry processing your message shortly."
		log.Printf("Chat error, created pending task for conv %d: %v", req.ConversationID, err)
	} else {
		response = formatResponseWithSources(response, toolsUsed)
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
	
	renderTemplate(w, r, "dev.html", map[string]interface{}{
		"Model":        anthropicModel,
		"Tools":        toolDefs,
		"Integrations": integrations,
	})
}

// requireAdmin wraps handlers that need admin access
func requireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getSession(r)
		if session == nil {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		
		// Check if user is admin
		if !db.IsAdmin(session.Email) {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		
		handler(w, r)
	}
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	accounts, _ := db.GetAccounts()
	users, _ := db.GetUsers()
	toolDefs := tools.GetTools()
	
	// Build integrations with enable/disable state
	integrations := []map[string]interface{}{
		{
			"Name":        "Anthropic Claude",
			"Key":         "anthropic",
			"Description": "AI model for chat responses",
			"Configured":  anthropicKey != "",
			"Enabled":     true, // Always enabled if configured
			"Toggleable":  false,
			"Details":     anthropicModel,
			"EnvVar":      "ANTHROPIC_API_KEY",
		},
		{
			"Name":        "Google OAuth",
			"Key":         "google_oauth",
			"Description": "User authentication",
			"Configured":  googleClientID != "" && googleClientSecret != "",
			"Enabled":     true, // Always enabled if configured
			"Toggleable":  false,
			"Details":     googleRedirectURI,
			"EnvVar":      "GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET",
		},
		{
			"Name":        "Brave Search",
			"Key":         "brave_search",
			"Description": "Web search via www tool",
			"Configured":  os.Getenv("BRAVE_API_KEY") != "",
			"Enabled":     os.Getenv("BRAVE_API_KEY") != "" && db.GetSetting("brave_search_enabled") != "false",
			"Toggleable":  true,
			"Details":     "2000 free queries/month",
			"EnvVar":      "BRAVE_API_KEY",
		},
		{
			"Name":        "Gmail (Assistant Inbox)",
			"Key":         "gmail",
			"Description": "Email via IMAP/SMTP for assistant@aslam.org",
			"Configured":  os.Getenv("GMAIL_USER") != "" && os.Getenv("GMAIL_APP_PASSWORD") != "",
			"Enabled":     os.Getenv("GMAIL_USER") != "" && db.GetSetting("gmail_enabled") != "false",
			"Toggleable":  true,
			"Details":     os.Getenv("GMAIL_USER"),
			"EnvVar":      "GMAIL_USER, GMAIL_APP_PASSWORD",
		},
	}
	
	// Get status info
	taskStats := db.GetTaskStats()
	emailStats := db.GetEmailStats()
	recentEmails, _ := db.GetRecentEmails(10)
	recentTasks, _ := db.GetRecentTasks(10)
	
	msg := r.URL.Query().Get("msg")
	errMsg := r.URL.Query().Get("error")
	
	renderTemplate(w, r, "admin.html", map[string]interface{}{
		"Accounts":     accounts,
		"Users":        users,
		"Integrations": integrations,
		"Tools":        toolDefs,
		"TaskStats":    taskStats,
		"EmailStats":   emailStats,
		"RecentEmails": recentEmails,
		"RecentTasks":  recentTasks,
		"CurrentUser":  session.Email,
		"Message":      msg,
		"Error":        errMsg,
	})
}

func handleAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	session := getSession(r)
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
	role := strings.TrimSpace(r.FormValue("role"))

	if email == "" {
		http.Redirect(w, r, "/admin?error=Email+required", http.StatusSeeOther)
		return
	}
	if role != "admin" && role != "user" {
		role = "user"
	}

	err := db.AddUser(email, name, role, session.Email)
	if err != nil {
		http.Redirect(w, r, "/admin?error=Failed+to+add+user", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/admin?msg=User+added", http.StatusSeeOther)
}

func handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin?error=Invalid+ID", http.StatusSeeOther)
		return
	}

	db.RemoveUser(id)
	http.Redirect(w, r, "/admin?msg=User+removed", http.StatusSeeOther)
}

func handleAddAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	
	service := strings.TrimSpace(r.FormValue("service"))
	accountID := strings.TrimSpace(r.FormValue("account_id"))
	password := r.FormValue("password") // Don't trim passwords
	apiKey := strings.TrimSpace(r.FormValue("api_key"))
	description := strings.TrimSpace(r.FormValue("description"))
	url := strings.TrimSpace(r.FormValue("url"))
	envVar := strings.TrimSpace(r.FormValue("env_var"))
	notes := strings.TrimSpace(r.FormValue("notes"))
	
	if service == "" {
		http.Redirect(w, r, "/admin?error=Service+name+required", http.StatusSeeOther)
		return
	}
	
	_, err := db.SaveAccount(service, accountID, password, apiKey, description, url, envVar, notes)
	if err != nil {
		http.Redirect(w, r, "/admin?error=Failed+to+save+account", http.StatusSeeOther)
		return
	}
	
	http.Redirect(w, r, "/admin?msg=Account+saved", http.StatusSeeOther)
}

func handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if id == 0 {
		http.Redirect(w, r, "/admin?error=Invalid+ID", http.StatusSeeOther)
		return
	}
	
	db.DeleteAccount(id)
	http.Redirect(w, r, "/admin?msg=Account+deleted", http.StatusSeeOther)
}

func handleToggleIntegration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	
	key := r.FormValue("key")
	enabled := r.FormValue("enabled") == "true"
	
	switch key {
	case "brave_search":
		db.SetSettingBool("brave_search_enabled", enabled)
	case "gmail":
		db.SetSettingBool("gmail_enabled", enabled)
	default:
		http.Redirect(w, r, "/admin?error=Unknown+integration", http.StatusSeeOther)
		return
	}
	
	http.Redirect(w, r, "/admin?msg=Integration+updated", http.StatusSeeOther)
}

// Toggle public/private handlers

func handleUpdateLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	session := getSession(r)
	if session == nil {
		jsonError(w, "Unauthorized", 401)
		return
	}
	var req struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		Timezone  string  `json:"timezone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}
	if req.Latitude == 0 && req.Longitude == 0 {
		jsonError(w, "Invalid coordinates", 400)
		return
	}
	db.UpdateUserLocation(session.Email, req.Latitude, req.Longitude, req.Timezone)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleToggleChatPublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ID     int64 `json:"id"`
		Public bool  `json:"public"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	// Verify ownership
	userID := getUserID(r)
	ownerID := db.GetConversationOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	if ownerID != 0 && ownerID != userID && !isAdmin {
		jsonError(w, "Access denied", 403)
		return
	}

	if err := db.ToggleConversationPublic(req.ID, req.Public); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleToggleNotePublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ID     int64 `json:"id"`
		Public bool  `json:"public"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	// Verify ownership
	userID := getUserID(r)
	ownerID := db.GetNoteOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	if ownerID != 0 && ownerID != userID && !isAdmin {
		jsonError(w, "Access denied", 403)
		return
	}

	if err := db.ToggleNotePublic(req.ID, req.Public); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Notes handlers

func handleProfile(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	user, err := db.GetUserByEmail(session.Email)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}

	if r.Method == "POST" {
		r.ParseMultipartForm(5 << 20) // 5MB max

		name := strings.TrimSpace(r.FormValue("name"))
		if name != "" {
			user.Name = name
		}

		// Handle picture upload — resize to 128px and base64 encode
		file, header, err := r.FormFile("picture")
		if err == nil && header != nil {
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, 2<<20)) // 2MB limit
			if err == nil && len(data) > 0 {
				resized := resizeAndEncode(data)
				if resized != "" {
					user.Picture = resized
				}
			}
		}

		if latStr := r.FormValue("latitude"); latStr != "" {
			if v, err := strconv.ParseFloat(latStr, 64); err == nil {
				user.Latitude = v
			}
		}
		if lngStr := r.FormValue("longitude"); lngStr != "" {
			if v, err := strconv.ParseFloat(lngStr, 64); err == nil {
				user.Longitude = v
			}
		}
		if tz := strings.TrimSpace(r.FormValue("timezone")); tz != "" {
			user.Timezone = tz
		}

		db.UpdateUserProfile(session.Email, user.Name, user.Picture)
		db.UpdateUserLocation(session.Email, user.Latitude, user.Longitude, user.Timezone)
		http.Redirect(w, r, "/profile?msg=Profile+updated", http.StatusSeeOther)
		return
	}

	renderTemplate(w, r, "profile.html", map[string]interface{}{
		"User":    user,
		"Message": r.URL.Query().Get("msg"),
	})
}

func resizeAndEncode(data []byte) string {
	// For simplicity, store as base64 data URI without resizing.
	// Go's stdlib doesn't include image resizing; we'd need a third-party lib.
	// Instead, just cap at reasonable size and encode.
	if len(data) > 500*1024 {
		return ""
	}
	mime := http.DetectContentType(data)
	if !strings.HasPrefix(mime, "image/") {
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return "data:" + mime + ";base64," + encoded
}

func handleNotes(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	items, err := db.GetNoteItems(userID)
	if err != nil {
		http.Error(w, "Failed to get note items", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Items":         items,
		"CurrentUserID": userID,
	}

	renderTemplate(w, r, "notes.html", data)
}

func handleNoteAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		title = strings.TrimSpace(r.FormValue("name"))
	}
	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		content = strings.TrimSpace(r.FormValue("details"))
	}

	if title == "" {
		http.Redirect(w, r, "/notes?error=Title+required", http.StatusSeeOther)
		return
	}

	userID := getUserID(r)
	_, err := db.AddNoteItem(title, content, userID)
	if err != nil {
		http.Redirect(w, r, "/notes?error=Failed+to+add+item", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/notes", http.StatusSeeOther)
}

func handleNoteEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/notes/edit/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	userID := getUserID(r)
	ownerID := db.GetNoteOwner(id)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	isOwner := ownerID == userID || ownerID == 0

	if r.Method == "POST" {
		// Only owner or admin can edit
		if !isOwner && !isAdmin {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		title := strings.TrimSpace(r.FormValue("title"))
		content := strings.TrimSpace(r.FormValue("content"))

		err := db.UpdateNoteItem(id, title, content)
		if err != nil {
			http.Redirect(w, r, "/notes?error=Failed+to+update", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	item, err := db.GetNoteItem(id)
	if err != nil {
		http.Redirect(w, r, "/notes?error=Item+not+found", http.StatusSeeOther)
		return
	}

	// Check access: owner, public, legacy, or admin
	if !isOwner && !item.Public && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	data := map[string]interface{}{
		"Item":    item,
		"IsOwner": isOwner || isAdmin,
	}
	renderTemplate(w, r, "notes_edit.html", data)
}

func handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/notes/delete/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	// Verify ownership: owner, legacy (no owner), or admin
	userID := getUserID(r)
	ownerID := db.GetNoteOwner(id)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	if ownerID != 0 && ownerID != userID && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	db.DeleteNoteItem(id)
	http.Redirect(w, r, "/notes?msg=Item+deleted", http.StatusSeeOther)
}
