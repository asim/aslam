package server

import (
	"crypto/rand"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"aslam/db"
	"aslam/internal/discovery"
	"aslam/internal/seerah"
	"aslam/internal/tools"
)

var buildVersion = strconv.FormatInt(time.Now().Unix(), 10)

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

// Run initializes the application and serves HTTP.
func Run() {
	// Load config
	loadEnv()

	anthropicKey = os.Getenv("ANTHROPIC_API_KEY")
	anthropicModel = os.Getenv("ANTHROPIC_MODEL")
	if anthropicModel == "" {
		anthropicModel = "claude-sonnet-5"
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

	var seerahErr error
	seerahBook, seerahErr = seerah.Load()
	if seerahErr != nil {
		log.Fatal(seerahErr)
	}
	if err := db.IndexSeerah(seerahBook); err != nil {
		log.Fatal("Seerah index: ", err)
	}

	seedUsers()

	go func() {
		loadIslamQA()
		loadGhazali()
		loadSources()
		loadAdhkar()
		loadRiyad()
		loadArabic()
		loadProphets()
	}()

	// Parse templates
	funcs := template.FuncMap{
		"version":   func() string { return buildVersion },
		"hasPrefix": strings.HasPrefix,
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04")
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"ghazaliParagraphs": ghazaliParagraphs,
		"paragraphs": func(s string) template.HTML {
			s = strings.ReplaceAll(s, "\r\n", "\n")
			paras := strings.Split(s, "\n\n")
			var out strings.Builder
			for _, p := range paras {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				lines := strings.Split(p, "\n")
				var merged strings.Builder
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					if i > 0 {
						prev := strings.TrimSpace(lines[i-1])
						if prev != "" && !strings.HasSuffix(prev, ".") && !strings.HasSuffix(prev, ":") && !strings.HasSuffix(prev, "?") && !strings.HasSuffix(prev, "!") && !strings.HasSuffix(prev, "\"") && !strings.HasSuffix(prev, ")") {
							merged.WriteString(" ")
						} else {
							merged.WriteString("<br>")
						}
					}
					merged.WriteString(template.HTMLEscapeString(line))
				}
				out.WriteString("<p>")
				out.WriteString(merged.String())
				out.WriteString("</p>")
			}
			return template.HTML(out.String())
		},
		"lines": func(s string) template.HTML {
			s = strings.ReplaceAll(s, "\r\n", "\n")
			var out strings.Builder
			for _, line := range strings.Split(s, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				out.WriteString("<p>")
				out.WriteString(template.HTMLEscapeString(line))
				out.WriteString("</p>")
			}
			return template.HTML(out.String())
		},
	}

	tmpl = template.Must(template.New("").Funcs(funcs).ParseFS(templates, "html/*.html"))

	// Auth routes (no auth required)
	http.HandleFunc("/auth/login", handleAuthLogin)
	http.HandleFunc("/auth/signup", handleSignup)
	http.HandleFunc("/auth/verify", handleVerify)
	http.HandleFunc("/privacy", handlePrivacy)
	http.HandleFunc("/auth/callback", handleOAuthCallback)
	http.HandleFunc("/auth/logout", handleLogout)

	// PWA static files (no auth)
	http.HandleFunc("/manifest.json", handleStatic("manifest.json", "application/json"))
	http.HandleFunc("/sw.js", handleStatic("sw.js", "application/javascript"))
	http.HandleFunc("/icon-192.png", handleStatic("icon-192.png", "image/png"))
	http.HandleFunc("/icon-512.png", handleStatic("icon-512.png", "image/png"))
	http.HandleFunc("/fonts/arabic.otf", handleStatic("arabic.otf", "font/otf"))
	http.HandleFunc("/app.css", handleStatic("app.css", "text/css"))
	http.HandleFunc("/app.js", handleStatic("app.js", "application/javascript"))

	// Public landing page
	discovery.RegisterRoutes(http.DefaultServeMux)
	http.HandleFunc("/", handleLanding)

	// Protected routes
	http.HandleFunc("/home", requireAuth(handleHome))
	http.HandleFunc("/chat", requireAuth(handleChat))
	http.HandleFunc("/chat/", requireAuth(handleChatView))
	http.HandleFunc("/chat/new", requireAuth(handleNewChat))
	http.HandleFunc("/chat/send", requireAuth(handleSendMessage))
	http.HandleFunc("/api/chat/send", requireAuth(handleAPISendMessage))
	http.HandleFunc("/api/chat/latest", requireAuth(handleAPIChatLatest))
	http.HandleFunc("/api/chat/new", requireAuth(handleAPINewChat))
	http.HandleFunc("/api/chat/delete", requireAuth(handleAPIDeleteChat))
	http.HandleFunc("/api/chats", requireAuth(handleAPIChats))
	http.HandleFunc("/api/search", optionalAuth(handleAPISearch))
	http.HandleFunc("/api/knowledge/search", handleKnowledgeSearch)
	http.HandleFunc("/api/knowledge/resource", handleKnowledgeResource)
	http.HandleFunc("/search", optionalAuth(handleSearch))
	http.HandleFunc("/entries", requireAuth(handleEntries))
	http.HandleFunc("/entries/", requireAuth(handleEntryView))
	http.HandleFunc("/islamqa", optionalAuth(handleIslamQAIndex))
	http.HandleFunc("/islamqa/", optionalAuth(handleIslamQAView))
	http.HandleFunc("/seerah", optionalAuth(handleSeerahIndex))
	http.HandleFunc("/seerah/page/", optionalAuth(handleSeerahPage))
	http.HandleFunc("/ghazali", optionalAuth(handleGhazaliIndex))
	http.HandleFunc("/ghazali/", optionalAuth(handleGhazaliView))
	http.HandleFunc("/adhkar", optionalAuth(handleAdhkarIndex))
	http.HandleFunc("/adhkar/", optionalAuth(handleAdhkarView))
	http.HandleFunc("/salihin", optionalAuth(handleRiyadIndex))
	http.HandleFunc("/salihin/", optionalAuth(handleRiyadView))
	http.HandleFunc("/arabic", optionalAuth(handleArabicIndex))
	http.HandleFunc("/arabic/", optionalAuth(handleArabicView))
	http.HandleFunc("/stories", optionalAuth(handleStoriesIndex))
	http.HandleFunc("/stories/", optionalAuth(handleStoriesView))
	http.HandleFunc("/api/arabic/search", requireAuth(handleArabicSearch))
	http.HandleFunc("/quran", optionalAuth(handleQuranIndex))
	http.HandleFunc("/quran/", optionalAuth(handleQuranRouter))
	http.HandleFunc("/hadith", optionalAuth(handleHadithIndex))
	http.HandleFunc("/hadith/", optionalAuth(handleHadithRouter))
	http.HandleFunc("/names", optionalAuth(handleNamesIndex))
	http.HandleFunc("/names/", optionalAuth(handleNameView))
	http.HandleFunc("/admin", requireAuth(requireAdmin(handleAdmin)))
	registerProfilingRoutes(http.DefaultServeMux)
	http.HandleFunc("/admin/add-user", requireAuth(requireAdmin(handleAddUser)))
	http.HandleFunc("/admin/remove-user", requireAuth(requireAdmin(handleRemoveUser)))
	http.HandleFunc("/admin/add-account", requireAuth(requireAdmin(handleAddAccount)))
	http.HandleFunc("/admin/delete-account", requireAuth(requireAdmin(handleDeleteAccount)))
	http.HandleFunc("/admin/toggle-integration", requireAuth(requireAdmin(handleToggleIntegration)))
	http.HandleFunc("/profile", requireAuth(handleProfile))
	http.HandleFunc("/notes", requireAuth(handleNotes))
	http.HandleFunc("/notes/", requireAuth(handleNoteView))
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
	tools.SetAdhkarSearcher(func(query string) ([]map[string]interface{}, error) {
		return db.SearchAdhkar(query)
	})
	tools.SetRiyadSearcher(func(query string) ([]map[string]interface{}, error) {
		return db.SearchRiyad(query)
	})

	log.Printf("System prompt length: %d", len(systemPrompt))
	log.Printf("Aslam running on http://localhost:%s", port)

	// Start background workers
	startTaskProcessor()      // Handles pending tasks from any channel
	startEmailWorker()        // Polls inbox for new emails
	startDailyContentWorker() // Fetches daily verse/hadith/name

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
