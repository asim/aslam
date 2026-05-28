package main

import (
	"archive/zip"
	"bufio"
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
	"regexp"
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

//go:embed data/islamqa.zip
var islamqaZip []byte

//go:embed data/ghazali.zip
var ghazaliZip []byte

//go:embed data/sources.zip
var sourcesZip []byte

//go:embed data/adhkar.zip
var adhkarZip []byte

//go:embed data/salihin.zip
var riyadZip []byte

//go:embed data/arabic.zip
var arabicZip []byte

//go:embed data/prophets.json
var prophetsJSON []byte

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
		loadAdhkar()
		loadRiyad()
		loadArabic()
		loadProphets()
	}()

	// Parse templates
	funcs := template.FuncMap{
		"version": func() string { return buildVersion },
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
	http.HandleFunc("/privacy", handlePrivacy)
	http.HandleFunc("/auth/callback", handleOAuthCallback)
	http.HandleFunc("/auth/logout", handleLogout)

	// PWA static files (no auth)
	http.HandleFunc("/manifest.json", handleStatic("manifest.json", "application/json"))
	http.HandleFunc("/sw.js", handleStatic("sw.js", "application/javascript"))
	http.HandleFunc("/icon-192.png", handleStatic("icon-192.png", "image/png"))
	http.HandleFunc("/icon-512.png", handleStatic("icon-512.png", "image/png"))
	http.HandleFunc("/fonts/arabic.otf", handleStatic("arabic.otf", "font/otf"))
	http.HandleFunc("/.well-known/assetlinks.json", handleStatic(".well-known/assetlinks.json", "application/json"))
	http.HandleFunc("/app.css", handleStatic("app.css", "text/css"))
	http.HandleFunc("/app.js", handleStatic("app.js", "application/javascript"))

	// Public landing page
	http.HandleFunc("/", handleLanding)

	// Protected routes
	http.HandleFunc("/home", requireAuth(handleHome))
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
	http.HandleFunc("/islamqa", requireAuth(handleIslamQAIndex))
	http.HandleFunc("/islamqa/", requireAuth(handleIslamQAView))
	http.HandleFunc("/ghazali", requireAuth(handleGhazaliIndex))
	http.HandleFunc("/ghazali/", requireAuth(handleGhazaliView))
	http.HandleFunc("/adhkar", requireAuth(handleAdhkarIndex))
	http.HandleFunc("/adhkar/", requireAuth(handleAdhkarView))
	http.HandleFunc("/salihin", requireAuth(handleRiyadIndex))
	http.HandleFunc("/salihin/", requireAuth(handleRiyadView))
	http.HandleFunc("/arabic", requireAuth(handleArabicIndex))
	http.HandleFunc("/arabic/", requireAuth(handleArabicView))
	http.HandleFunc("/images/", handleImages)
	http.HandleFunc("/stories", requireAuth(handleStoriesIndex))
	http.HandleFunc("/stories/", requireAuth(handleStoriesView))
	http.HandleFunc("/api/arabic/search", requireAuth(handleArabicSearch))
	http.HandleFunc("/quran", requireAuth(handleQuranIndex))
	http.HandleFunc("/quran/", requireAuth(handleQuranRouter))
	http.HandleFunc("/hadith", requireAuth(handleHadithIndex))
	http.HandleFunc("/hadith/", requireAuth(handleHadithRouter))
	http.HandleFunc("/names", requireAuth(handleNamesIndex))
	http.HandleFunc("/names/", requireAuth(handleNameView))
	http.HandleFunc("/admin", requireAuth(requireAdmin(handleAdmin)))
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
	return db.SearchAll(query, userID, false)
}

// noteStorage implements tools.NoteStorage interface
type noteStorage struct{}

func (v *noteStorage) AddNoteItem(title, content string, userID int64) (int64, error) {
	return db.AddNoteItem(title, content, userID)
}

func (v *noteStorage) SearchNotes(query string, userID int64) ([]map[string]interface{}, error) {
	items, err := db.SearchNotes(query, userID, false)
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

const islamqaVersion = "3"

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
const ghazaliVersion = "2"

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

const sourcesVersion = "5"

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
					Number  int    `json:"number"`
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
					if err := db.InsertHadith(book.Name, book.Number, h.Number, h.Narrator, h.English, h.Arabic); err != nil {
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

const adhkarVersion = "2"

func loadAdhkar() {
	if db.GetSetting("adhkar_version") == adhkarVersion {
		log.Printf("Adhkar v%s already loaded (%d entries)", adhkarVersion, db.AdhkarCount())
		return
	}

	log.Printf("Loading Adhkar dataset v%s...", adhkarVersion)
	db.ClearAdhkar()

	r, err := zip.NewReader(bytes.NewReader(adhkarZip), int64(len(adhkarZip)))
	if err != nil {
		log.Printf("Failed to open adhkar.zip: %v", err)
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
			Title       string `json:"title"`
			Arabic      string `json:"arabic"`
			Latin       string `json:"latin"`
			Translation string `json:"translation"`
			Notes       string `json:"notes"`
			Benefits    string `json:"benefits"`
			Fawaid      string `json:"fawaid"`
			Source      string `json:"source"`
			Category    string `json:"category"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()
		for _, e := range entries {
			benefits := e.Benefits
			if benefits == "" {
				benefits = e.Fawaid
			}
			if err := db.InsertAdhkar(e.Category, e.Title, e.Arabic, e.Latin, e.Translation, e.Notes, benefits, e.Source); err != nil {
				log.Printf("Failed to insert adhkar entry: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("adhkar_version", adhkarVersion)
	log.Printf("Loaded %d adhkar entries (v%s)", total, adhkarVersion)
}

func handleAdhkarIndex(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	data := map[string]interface{}{}

	categories, _ := db.GetAdhkarCategories()
	data["Categories"] = categories

	if category != "" {
		items, _ := db.GetAdhkarByCategory(category)
		data["Items"] = items
		data["SelectedCategory"] = category
	} else {
		items, _ := db.GetAllAdhkar()
		data["Items"] = items
	}

	p, t := db.GetReadingProgress(getUserID(r), "adhkar")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "adhkar_index.html", data)
}

func handleAdhkarView(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/adhkar/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetAdhkar(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetAdhkarPrevNext(slug)
	item["PrevSlug"] = prev
	item["NextSlug"] = next
	db.SaveReadingProgress(getUserID(r), "adhkar", r.URL.Path, item["Title"].(string))
	renderTemplate(w, r, "adhkar.html", item)
}

const riyadVersion = "3"

func loadRiyad() {
	if db.GetSetting("riyad_version") == riyadVersion {
		log.Printf("Riyad us-Salihin v%s already loaded (%d hadiths)", riyadVersion, db.RiyadCount())
		return
	}

	log.Printf("Loading Riyad us-Salihin dataset v%s...", riyadVersion)
	db.ClearRiyad()

	r, err := zip.NewReader(bytes.NewReader(riyadZip), int64(len(riyadZip)))
	if err != nil {
		log.Printf("Failed to open salihin.zip: %v", err)
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
		var data struct {
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
		if err := json.NewDecoder(rc).Decode(&data); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()
		for _, book := range data.Books {
			for _, h := range book.Hadiths {
				if err := db.InsertRiyad(book.Name, h.Number, h.Narrator, h.English, h.Arabic); err != nil {
					log.Printf("Failed to insert Riyad hadith %d: %v", h.Number, err)
				} else {
					total++
				}
			}
		}
	}

	db.SetSetting("riyad_version", riyadVersion)
	log.Printf("Loaded %d Riyad us-Salihin hadiths (v%s)", total, riyadVersion)
}

func handleRiyadIndex(w http.ResponseWriter, r *http.Request) {
	book := r.URL.Query().Get("book")
	data := map[string]interface{}{}

	books, _ := db.GetRiyadBooks()
	data["Books"] = books

	if book != "" {
		items, _ := db.GetRiyadByBook(book)
		data["Items"] = items
		data["SelectedBook"] = book
	}

	p, t := db.GetReadingProgress(getUserID(r), "salihin")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "salihin_index.html", data)
}

func handleRiyadView(w http.ResponseWriter, r *http.Request) {
	numStr := strings.TrimPrefix(r.URL.Path, "/salihin/")
	number, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetRiyad(number)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetRiyadPrevNext(number)
	item["PrevNumber"] = prev
	item["NextNumber"] = next
	db.SaveReadingProgress(getUserID(r), "salihin", r.URL.Path, fmt.Sprintf("Hadith %d", number))
	renderTemplate(w, r, "salihin.html", item)
}

const arabicVersion = "1"

func loadArabic() {
	if db.GetSetting("arabic_version") == arabicVersion {
		log.Printf("Arabic vocab v%s already loaded (%d words)", arabicVersion, db.ArabicCount())
		return
	}

	log.Printf("Loading Arabic vocab dataset v%s...", arabicVersion)
	db.ClearArabic()

	r, err := zip.NewReader(bytes.NewReader(arabicZip), int64(len(arabicZip)))
	if err != nil {
		log.Printf("Failed to open arabic.zip: %v", err)
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
			Arabic          string `json:"arabic"`
			Transliteration string `json:"transliteration"`
			English         string `json:"english"`
			Frequency       int    `json:"frequency"`
			ExampleRef      string `json:"example_ref"`
			Type            string `json:"type"`
		}
		if err := json.NewDecoder(rc).Decode(&entries); err != nil {
			rc.Close()
			log.Printf("Failed to decode %s: %v", f.Name, err)
			continue
		}
		rc.Close()
		for _, e := range entries {
			if err := db.InsertArabicWord(e.Arabic, e.Transliteration, e.English, e.Frequency, e.ExampleRef, e.Type); err != nil {
				log.Printf("Failed to insert Arabic word: %v", err)
			} else {
				total++
			}
		}
	}

	db.SetSetting("arabic_version", arabicVersion)
	log.Printf("Loaded %d Arabic vocab words (v%s)", total, arabicVersion)
}

const prophetsVersion = "1"

func loadProphets() {
	if db.GetSetting("prophets_version") == prophetsVersion {
		log.Printf("Prophets v%s already loaded (%d entries)", prophetsVersion, db.ProphetCount())
		return
	}

	log.Printf("Loading Prophets dataset v%s...", prophetsVersion)
	db.ClearProphets()

	var prophets []struct {
		Name        string `json:"name"`
		Arabic      string `json:"arabic"`
		Title       string `json:"title"`
		Summary     string `json:"summary"`
		Verses      []struct {
			Ref         string `json:"ref"`
			Chapter     int    `json:"chapter"`
			Start       int    `json:"start"`
			End         int    `json:"end"`
			Context     string `json:"context"`
			ImagePrompt string `json:"image_prompt"`
		} `json:"verses"`
	}
	if err := json.Unmarshal(prophetsJSON, &prophets); err != nil {
		log.Printf("Failed to parse prophets.json: %v", err)
		return
	}

	total := 0
	for i, p := range prophets {
		slug := strings.ToLower(p.Name)
		slug = strings.ReplaceAll(slug, " ", "-")
		slug = strings.ReplaceAll(slug, "'", "")
		versesJSON, _ := json.Marshal(p.Verses)
		if err := db.InsertProphet(slug, p.Name, p.Arabic, p.Title, p.Summary, string(versesJSON), "", i); err != nil {
			log.Printf("Failed to insert prophet %s: %v", p.Name, err)
		} else {
			total++
		}
	}

	db.SetSetting("prophets_version", prophetsVersion)
	log.Printf("Loaded %d prophets (v%s)", total, prophetsVersion)

	// Generate section images in background
	atlasKey := os.Getenv("ATLAS_API_KEY")
	if atlasKey == "" {
		log.Println("ATLAS_API_KEY not set, skipping story image generation")
		return
	}
	go generateStoryImages(prophets, atlasKey)
}

func generateStoryImages(prophets []struct {
	Name    string `json:"name"`
	Arabic  string `json:"arabic"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Verses  []struct {
		Ref         string `json:"ref"`
		Chapter     int    `json:"chapter"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
		Context     string `json:"context"`
		ImagePrompt string `json:"image_prompt"`
	} `json:"verses"`
}, atlasKey string) {
	imgDir := filepath.Join(os.Getenv("HOME"), ".aslam", "images")
	os.MkdirAll(imgDir, 0755)

	for _, p := range prophets {
		slug := strings.ToLower(p.Name)
		slug = strings.ReplaceAll(slug, " ", "-")
		slug = strings.ReplaceAll(slug, "'", "")

		for i, v := range p.Verses {
			if v.ImagePrompt == "" {
				continue
			}
			imgName := fmt.Sprintf("%s-%d.png", slug, i)
			imgPath := filepath.Join(imgDir, imgName)
			if _, err := os.Stat(imgPath); err == nil {
				continue
			}

			log.Printf("Generating image: %s section %d (%s)...", p.Name, i, v.Context)
			_, err := generateAtlasImage(v.ImagePrompt, atlasKey, fmt.Sprintf("%s-%d", slug, i))
			if err != nil {
				log.Printf("Failed to generate image %s-%d: %v", slug, i, err)
				continue
			}
			log.Printf("Generated image: %s", imgName)
			time.Sleep(3 * time.Second)
		}
	}
	log.Println("Story image generation complete")
}

func generateAtlasImage(prompt, apiKey, slug string) (string, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":           "openai/gpt-image-2",
		"prompt":          prompt,
		"n":               1,
		"size":            "1024x1024",
		"response_format": "b64_json",
	})

	req, _ := http.NewRequest("POST", "https://api.atlascloud.ai/v1/images/generations", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}

	var result struct {
		Data []struct {
			B64JSON string `json:"b64_json"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil || len(result.Data) == 0 {
		return "", fmt.Errorf("failed to parse image response")
	}

	// Decode and save as file
	imgData, err := base64.StdEncoding.DecodeString(result.Data[0].B64JSON)
	if err != nil {
		return "", err
	}

	// Save to a static path
	imgDir := filepath.Join(os.Getenv("HOME"), ".aslam", "images")
	os.MkdirAll(imgDir, 0755)
	imgPath := filepath.Join(imgDir, slug+".png")
	if err := os.WriteFile(imgPath, imgData, 0644); err != nil {
		return "", err
	}

	return "/images/" + slug + ".png", nil
}

func handleImages(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	imgPath := filepath.Join(os.Getenv("HOME"), ".aslam", "images", name)
	http.ServeFile(w, r, imgPath)
}

func handleStoriesIndex(w http.ResponseWriter, r *http.Request) {
	prophets, _ := db.GetAllProphets()
	imgDir := filepath.Join(os.Getenv("HOME"), ".aslam", "images")
	for _, p := range prophets {
		slug, _ := p["Slug"].(string)
		imgPath := filepath.Join(imgDir, slug+"-0.png")
		if _, err := os.Stat(imgPath); err == nil {
			p["ImageURL"] = "/images/" + slug + "-0.png"
		}
	}
	p, t := db.GetReadingProgress(getUserID(r), "stories")
	renderTemplate(w, r, "stories_index.html", map[string]interface{}{
		"Prophets":      prophets,
		"ContinuePath":  p,
		"ContinueTitle": t,
	})
}

func handleStoriesView(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/stories/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	prophet, err := db.GetProphet(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Parse verses JSON and fetch actual Quran text
	var verseRefs []struct {
		Ref     string `json:"ref"`
		Chapter int    `json:"chapter"`
		Start   int    `json:"start"`
		End     int    `json:"end"`
		Context string `json:"context"`
	}
	versesJSON, _ := prophet["VersesJSON"].(string)
	json.Unmarshal([]byte(versesJSON), &verseRefs)

	type VerseSection struct {
		Ref      string
		Context  string
		Chapter  int
		Start    int
		End      int
		Verses   []map[string]interface{}
		ImageURL string
	}
	var sections []VerseSection
	for i, vr := range verseRefs {
		verses, _ := db.GetQuranVerseRange(vr.Chapter, vr.Start, vr.End)
		imgName := fmt.Sprintf("%s-%d.png", slug, i)
		imgPath := filepath.Join(os.Getenv("HOME"), ".aslam", "images", imgName)
		imgURL := ""
		if _, err := os.Stat(imgPath); err == nil {
			imgURL = "/images/" + imgName
		}
		sections = append(sections, VerseSection{
			Ref:      vr.Ref,
			Context:  vr.Context,
			Chapter:  vr.Chapter,
			Start:    vr.Start,
			End:      vr.End,
			Verses:   verses,
			ImageURL: imgURL,
		})
	}
	prophet["Sections"] = sections

	prev, next := db.GetProphetPrevNext(slug)
	prophet["PrevSlug"] = prev
	prophet["NextSlug"] = next

	db.SaveReadingProgress(getUserID(r), "stories", r.URL.Path, prophet["Name"].(string))
	renderTemplate(w, r, "stories.html", prophet)
}

func handleArabicIndex(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	level := r.URL.Query().Get("level")
	data := map[string]interface{}{}

	// Levels: each is 50 words by frequency
	levels := []map[string]interface{}{
		{"Level": 1, "Label": "Essential (1-50)", "Desc": "The 50 most frequent words — covers ~25% of the Quran"},
		{"Level": 2, "Label": "Core (51-100)", "Desc": "The next 50 most common words"},
		{"Level": 3, "Label": "Common (101-200)", "Desc": "100 more frequently used words"},
		{"Level": 4, "Label": "Intermediate (201-500)", "Desc": "300 words to deepen your vocabulary"},
		{"Level": 5, "Label": "Advanced (501-1000)", "Desc": "500 words for strong comprehension"},
	}
	data["Levels"] = levels

	if query != "" {
		results, _ := db.SearchArabic(query)
		data["Words"] = results
		data["Query"] = query
	} else if level != "" {
		lvl, _ := strconv.Atoi(level)
		var offset, limit int
		switch lvl {
		case 1: offset, limit = 0, 50
		case 2: offset, limit = 50, 50
		case 3: offset, limit = 100, 100
		case 4: offset, limit = 200, 300
		case 5: offset, limit = 500, 500
		default: offset, limit = 0, 50; lvl = 1
		}
		words, _ := db.GetArabicByFrequencyRange(offset, limit)
		data["Words"] = words
		data["SelectedLevel"] = lvl
	} else {
		words, _ := db.GetArabicByFrequency(50)
		data["Words"] = words
		data["SelectedLevel"] = 1
	}

	p, t := db.GetReadingProgress(getUserID(r), "arabic")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "arabic_index.html", data)
}

func handleArabicView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/arabic/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetArabicWord(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prevID, nextID := db.GetArabicPrevNext(id)
	item["PrevID"] = prevID
	item["NextID"] = nextID

	// Parse example_ref like "Al-Fatihah 1:1" to fetch the verse
	if ref, ok := item["ExampleRef"].(string); ok && ref != "" {
		if m := regexp.MustCompile(`(\d+):(\d+)$`).FindStringSubmatch(ref); m != nil {
			ch, _ := strconv.Atoi(m[1])
			v, _ := strconv.Atoi(m[2])
			if verse, err := db.GetQuranVerse(ch, v); err == nil {
				item["Verse"] = verse
				item["VerseURL"] = fmt.Sprintf("/quran/%d/%d", ch, v)
				item["VerseWBW"] = fmt.Sprintf("https://reminder.dev/quran/%d?wbw=1#%d", ch, v)
			}
		}
	}

	translit, _ := item["Transliteration"].(string)
	db.SaveReadingProgress(getUserID(r), "arabic", r.URL.Path, translit)
	renderTemplate(w, r, "arabic.html", item)
}

func handleArabicSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"results": []interface{}{}})
		return
	}

	results, err := db.SearchArabic(query)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}
	if results == nil {
		results = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

func handleQuranIndex(w http.ResponseWriter, r *http.Request) {
	chapters, _ := db.GetQuranChapters()
	p, t := db.GetReadingProgress(getUserID(r), "quran")
	renderTemplate(w, r, "quran_index.html", map[string]interface{}{
		"Chapters":      chapters,
		"ContinuePath":  p,
		"ContinueTitle": t,
	})
}

func handleQuranRouter(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/quran/")
	if strings.Contains(path, "/") {
		handleQuranView(w, r)
		return
	}
	chapter, err := strconv.Atoi(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	verses, _ := db.GetQuranChapter(chapter)
	if len(verses) == 0 {
		http.NotFound(w, r)
		return
	}
	first, _ := db.GetQuranVerse(chapter, 1)
	name := ""
	if first != nil {
		if n, ok := first["ChapterName"].(string); ok {
			name = n
		}
	}
	renderTemplate(w, r, "quran_chapter.html", map[string]interface{}{
		"Chapter":     chapter,
		"ChapterName": name,
		"Verses":      verses,
	})
}

func handleHadithIndex(w http.ResponseWriter, r *http.Request) {
	books, _ := db.GetHadithBooks()
	renderTemplate(w, r, "hadith_index.html", map[string]interface{}{"Books": books})
}

func handleHadithRouter(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/hadith/")
	if strings.HasPrefix(path, "book/") {
		bookStr := strings.TrimPrefix(path, "book/")
		bookNum, err := strconv.ParseInt(bookStr, 10, 64)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		items, _ := db.GetHadithByBook(bookNum)
		if len(items) == 0 {
			http.NotFound(w, r)
			return
		}
		books, _ := db.GetHadithBooks()
		bookName := ""
		for _, b := range books {
			if b["BookNumber"] == bookNum {
				bookName, _ = b["Book"].(string)
				break
			}
		}
		renderTemplate(w, r, "hadith_book.html", map[string]interface{}{
			"BookNumber": bookNum,
			"BookName":   bookName,
			"Items":      items,
		})
		return
	}
	handleHadithView(w, r)
}

func handleNamesIndex(w http.ResponseWriter, r *http.Request) {
	names, _ := db.GetAllNames()
	renderTemplate(w, r, "names_index.html", map[string]interface{}{"Names": names})
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
	chName, _ := item["ChapterName"].(string)
	db.SaveReadingProgress(getUserID(r), "quran", r.URL.Path, fmt.Sprintf("%s %d:%d", chName, chapter, verse))
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
	idStr := strings.TrimPrefix(r.URL.Path, "/names/")
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

		// Accept session token from URL (OAuth redirect into PWA)
		if authToken := r.URL.Query().Get("auth"); authToken != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    authToken,
				Path:     "/",
				Domain:   "aslam.org",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   30 * 24 * 60 * 60,
				Expires:  time.Now().Add(30 * 24 * time.Hour),
			})
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
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

func handlePrivacy(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, r, "privacy.html", nil)
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
	if email == "" || !strings.Contains(email, "@") || !strings.Contains(email[strings.Index(email, "@"):], ".") {
		tmpl.ExecuteTemplate(w, "signup.html", map[string]interface{}{
			"Error":         "Please enter a valid email address",
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
	http.Redirect(w, r, "/home?auth="+url.QueryEscape(token), http.StatusSeeOther)
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

func isAdminReq(r *http.Request) bool {
	session := getSession(r)
	if session == nil {
		return false
	}
	return db.IsAdmin(session.Email)
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
	convs, _ := db.GetRecentConversations(10, userID, true, isAdminReq(r))
	dailyContent, _ := db.GetLatestReminderContent()
	randomQA, _ := db.GetRandomIslamQA()

	hasLocation := false
	if userID > 0 {
		if u, err := db.GetUserByID(userID); err == nil {
			hasLocation = u.Latitude != 0 || u.Longitude != 0
		}
	}

	renderTemplate(w, r, "home.html", map[string]interface{}{
		"Conversations":   convs,
		"DailyContent":    dailyContent,
		"RandomQA":        randomQA,
		"PrayerTimes":     getPrayerTimesForUser(userID),
		"HasLocation":     hasLocation,
		"ReadingProgress": db.GetAllReadingProgress(userID),
	})
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	showAll := r.URL.Query().Get("show") == "all"
	convs, _ := db.GetRecentConversations(50, userID, !showAll, isAdminReq(r))
	renderTemplate(w, r, "chat_list.html", map[string]interface{}{
		"Conversations": convs,
		"CurrentUserID": userID,
		"ShowAll":       showAll,
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

	// Access check: owner, public, or admin. Orphaned chats (user_id IS NULL)
	// are admin-only until they get adopted by an update.
	isOwner := userID != 0 && conv.UserID == userID
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

	db.AdoptOrphanConversation(convID, getUserID(r))

	// Save user message
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	
	// Get conversation history for context
	messages, _ := db.GetMessages(convID)
	
	// Generate AI response
	response, toolsUsed, err := generateResponse(messages, convID)
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

	db.AdoptOrphanConversation(req.ConversationID, getUserID(r))

	// Save user message
	if err := db.AddMessage(req.ConversationID, "user", req.Message); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	messages, _ := db.GetMessages(req.ConversationID)

	// Update conversation title if first message
	if len(messages) <= 1 {
		title := req.Message
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		db.UpdateConversationTitle(req.ConversationID, title)
	}

	// Stream response as chunked HTTP
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "Streaming not supported", 500)
		return
	}

	response, toolsUsed, err := generateResponseStreaming(messages, req.ConversationID, func(text string) {
		fmt.Fprint(w, text)
		flusher.Flush()
	})
	if err != nil {
		response = "Error: " + err.Error()
		fmt.Fprint(w, response)
		flusher.Flush()
	} else {
		response = formatResponseWithSources(response, toolsUsed)
	}
	db.AddMessage(req.ConversationID, "assistant", response)
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

	// Verify ownership: owner or admin. Orphans (ownerID == 0) are admin-only.
	userID := getUserID(r)
	ownerID := db.GetConversationOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
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
	convs, err := db.GetRecentConversations(50, userID, true, isAdminReq(r))
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
	results, err := db.SearchAll(query, userID, isAdminReq(r))
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
		results, _ = db.SearchAll(query, userID, isAdminReq(r))
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
	slug := strings.TrimPrefix(r.URL.Path, "/ghazali/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetGhazali(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetGhazaliPrevNext(slug)
	item["PrevSlug"] = prev
	item["NextSlug"] = next
	db.SaveReadingProgress(getUserID(r), "ghazali", r.URL.Path, item["Chapter"].(string))
	renderTemplate(w, r, "ghazali.html", item)
}

func handleGhazaliIndex(w http.ResponseWriter, r *http.Request) {
	volumeStr := r.URL.Query().Get("volume")
	data := map[string]interface{}{}

	if volumeStr != "" {
		volume, err := strconv.Atoi(volumeStr)
		if err == nil {
			chapters, _ := db.GetGhazaliByVolume(volume)
			data["Chapters"] = chapters
			data["SelectedVolume"] = volume
		}
	} else {
		chapters, _ := db.GetGhazaliChapters()
		data["Chapters"] = chapters
	}

	p, t := db.GetReadingProgress(getUserID(r), "ghazali")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "ghazali_index.html", data)
}

func handleIslamQAView(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/islamqa/")
	if slug == "" {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetIslamQA(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, next := db.GetIslamQAPrevNext(slug)
	item["PrevSlug"] = prev
	item["NextSlug"] = next
	q, _ := item["Question"].(string)
	if len(q) > 60 {
		q = q[:60] + "..."
	}
	db.SaveReadingProgress(getUserID(r), "islamqa", r.URL.Path, q)
	renderTemplate(w, r, "islamqa.html", item)
}

func handleIslamQAIndex(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	data := map[string]interface{}{}

	categories, _ := db.GetIslamQACategories()
	data["Categories"] = categories

	if category != "" {
		questions, _ := db.GetIslamQAByCategory(category)
		data["Questions"] = questions
		data["SelectedCategory"] = category
	} else {
		questions, _ := db.GetAllIslamQA()
		data["Questions"] = questions
	}

	p, t := db.GetReadingProgress(getUserID(r), "islamqa")
	data["ContinuePath"] = p
	data["ContinueTitle"] = t

	renderTemplate(w, r, "islamqa_index.html", data)
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

var systemPromptTemplate = `You are an Islamic knowledge assistant. Your purpose is to help Muslims seek, understand, and save Islamic knowledge from authentic sources.

You have access to a knowledge base containing the Quran, Sahih al-Bukhari, 99 Names of Allah, scholarly Q&A (IslamQA), Imam Al-Ghazali's Ihya Ulum al-Din, Riyad us-Salihin, daily adhkar, and Quranic Arabic vocabulary — over 40,000 indexed records from authentic Islamic sources.

SCOPE:
You answer questions about Islam, the Quran, Hadith, fiqh, aqeedah, history, manners, spirituality, and daily practice. When a question touches everyday life (finance, food, health, relationships, parenting), answer from an Islamic perspective using the sources available to you.

Politely decline questions that have no Islamic relevance. You are not a general-purpose assistant. If someone asks about programming, sports scores, or unrelated topics, respond briefly: "I'm here to help with Islamic knowledge. You might find a general search engine more helpful for that." Do not answer the question.

TOOLS:
- search: Search the full knowledge base (Quran, Hadith, Names, IslamQA, Ghazali, Adhkar, Salihin, notes).
- reminder: Semantic search across Quran, Hadith, and Names of Allah via the reminder API.
- islamqa: Search IslamQA for scholarly answers.
- ghazali: Search Imam Al-Ghazali's Ihya Ulum al-Din.
- adhkar: Search duas and dhikr.
- salihin: Search Riyad us-Salihin.
- fetch: Fetch a URL — use only for Islamic content (articles, fatawa, lectures).
- web_search: Search the web — use only for Islamic topics (scholar opinions, Islamic history, halal/haram rulings).
- note_add / note_update: Save knowledge the user wants to keep.

Always search the knowledge base before searching the web. Prefer authentic sourced content over web results.

QUERY REFORMULATION:
The knowledge base uses keyword search (FTS), not semantic search. When calling search, islamqa, ghazali, adhkar, or salihin tools:
- Reformulate natural language into search keywords
- Use synonyms: "anger" → also try "wrath", "rage"
- Include Arabic transliterations: "patience" → also try "sabr"
- Include related Islamic concepts: "dealing with loss" → try "patience adversity", "qadr"
- Strip filler words: "how do I deal with anger" → "controlling anger"
- Call a tool multiple times with different queries rather than missing content
- For the reminder tool (semantic search), pass natural language directly

TONE:
- Be concise and direct. Cite your sources (which surah, which hadith, which scholar).
- Do not pretend to be a scholar. Say "scholars have said" or "according to IslamQA" — never issue rulings yourself.
- When there is scholarly disagreement, present the main positions fairly.
- Do not add excessive Islamic greetings or phrases unless the user does first.
- Do not be preachy. Present knowledge; let the user reflect.
- Be humble. You are a tool to help find knowledge, not a source of authority.`

var systemPrompt string

func init() {
	systemPrompt = systemPromptTemplate
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

	seen := make(map[string]bool)
	var sources strings.Builder
	sources.WriteString("\n\n---\n**Sources:**\n")
	for _, tool := range toolsUsed {
		key := tool.Name + ":" + tool.Input
		if seen[key] {
			continue
		}
		seen[key] = true
		sources.WriteString(fmt.Sprintf("- %s: `%s`\n", tool.Name, tool.Input))
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

func generateResponse(messages []db.Message, convID int64) (string, []ToolUsage, error) {
	return generateResponseWithProgress(messages, convID, nil)
}

func generateResponseWithProgress(messages []db.Message, convID int64, onTool func(string)) (string, []ToolUsage, error) {
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
		role := m.Role
		if role == "context" || role == "tool" {
			role = "assistant"
		}
		apiMessages = append(apiMessages, map[string]interface{}{
			"role":    role,
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
			var contextLines []string
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

					contextLines = append(contextLines, fmt.Sprintf("[%s(%s): %s]", block.Name, string(inputJSON), truncateString(toolResult, 1000)))
				}
			}

			// Add tool results as user message
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})

			// Save a text summary so the AI can reference it in follow-up turns
			if convID > 0 && len(contextLines) > 0 {
				db.AddMessage(convID, "context", strings.Join(contextLines, "\n"))
			}
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

func generateResponseStreaming(messages []db.Message, convID int64, onText func(string)) (string, []ToolUsage, error) {
	var toolsUsed []ToolUsage
	if anthropicKey == "" {
		return "", nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	fullSystemPrompt := systemPrompt
	if currentUserContext != nil && currentUserContext.Email != "" {
		fullSystemPrompt += fmt.Sprintf("\n\nCurrent user: %s", currentUserContext.Email)
		if currentUserContext.Name != "" {
			fullSystemPrompt += fmt.Sprintf(" (%s)", currentUserContext.Name)
		}
	}

	var apiMessages []map[string]interface{}
	for _, m := range messages {
		if m.Role == "system" {
			continue
		}
		role := m.Role
		if role == "context" || role == "tool" {
			role = "assistant"
		}
		apiMessages = append(apiMessages, map[string]interface{}{
			"role":    role,
			"content": m.Content,
		})
	}

	for i := 0; i < 10; i++ {
		result, textSoFar, err := callAnthropicStream(apiMessages, fullSystemPrompt, onText)
		if err != nil {
			return "", toolsUsed, err
		}

		if result.StopReason == "tool_use" {
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "assistant",
				"content": result.Content,
			})

			var toolResults []map[string]interface{}
			var contextLines []string
			for _, block := range result.Content {
				if block.Type == "tool_use" {
					inputJSON, _ := json.Marshal(block.Input)
					log.Printf("Tool call: %s(%v)", block.Name, block.Input)
					toolResult, err := tools.ExecuteTool(block.Name, block.Input)
					if err != nil {
						toolResult = fmt.Sprintf("Error: %v", err)
					}
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
					contextLines = append(contextLines, fmt.Sprintf("[%s(%s): %s]", block.Name, string(inputJSON), truncateString(toolResult, 1000)))
				}
			}
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})
			if convID > 0 && len(contextLines) > 0 {
				db.AddMessage(convID, "context", strings.Join(contextLines, "\n"))
			}
			continue
		}

		if textSoFar == "" {
			return "Done.", toolsUsed, nil
		}
		return textSoFar, toolsUsed, nil
	}
	return "", toolsUsed, fmt.Errorf("too many tool calls")
}

func callAnthropicStream(apiMessages []map[string]interface{}, sysPrompt string, onText func(string)) (*anthropicResponse, string, error) {
	reqBody := map[string]interface{}{
		"model":      anthropicModel,
		"max_tokens": 4096,
		"tools":      tools.GetTools(),
		"system":     sysPrompt,
		"messages":   apiMessages,
		"stream":     true,
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse SSE stream from Anthropic
	var fullText strings.Builder
	var contentBlocks []contentBlock
	var currentToolInput strings.Builder
	var currentToolID, currentToolName string
	stopReason := ""

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var event struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type  string `json:"type"`
				ID    string `json:"id"`
				Name  string `json:"name"`
				Text  string `json:"text"`
				Input json.RawMessage `json:"input"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Message struct {
				StopReason string `json:"stop_reason"`
			} `json:"message"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		switch event.Type {
		case "content_block_start":
			if event.ContentBlock.Type == "tool_use" {
				currentToolID = event.ContentBlock.ID
				currentToolName = event.ContentBlock.Name
				currentToolInput.Reset()
			}
		case "content_block_delta":
			if event.Delta.Type == "text_delta" && event.Delta.Text != "" {
				fullText.WriteString(event.Delta.Text)
				if onText != nil {
					onText(event.Delta.Text)
				}
			} else if event.Delta.Type == "input_json_delta" {
				currentToolInput.WriteString(event.Delta.PartialJSON)
			}
		case "content_block_stop":
			if currentToolName != "" {
				var input map[string]interface{}
				json.Unmarshal([]byte(currentToolInput.String()), &input)
				contentBlocks = append(contentBlocks, contentBlock{
					Type:  "tool_use",
					ID:    currentToolID,
					Name:  currentToolName,
					Input: input,
				})
				currentToolName = ""
			} else if fullText.Len() > 0 {
				contentBlocks = append(contentBlocks, contentBlock{
					Type: "text",
					Text: fullText.String(),
				})
			}
		case "message_delta":
			if event.Delta.StopReason != "" {
				stopReason = event.Delta.StopReason
			}
		}
	}

	return &anthropicResponse{
		Content:    contentBlocks,
		StopReason: stopReason,
	}, fullText.String(), nil
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

	datasets := []map[string]interface{}{
		dataset("Quran", db.QuranCount(), 6348, db.GetSetting("sources_version"), sourcesVersion),
		dataset("Hadith", db.HadithCount(), 7265, db.GetSetting("sources_version"), sourcesVersion),
		dataset("Names of Allah", db.NamesCount(), 99, db.GetSetting("sources_version"), sourcesVersion),
		dataset("IslamQA", db.IslamQACount(), 4203, db.GetSetting("islamqa_version"), islamqaVersion),
		dataset("Ghazali", db.GhazaliCount(), 1437, db.GetSetting("ghazali_version"), ghazaliVersion),
		dataset("Adhkar", db.AdhkarCount(), 97, db.GetSetting("adhkar_version"), adhkarVersion),
		dataset("Riyad us-Salihin", db.RiyadCount(), 1896, db.GetSetting("riyad_version"), riyadVersion),
		dataset("Arabic", db.ArabicCount(), 21247, db.GetSetting("arabic_version"), arabicVersion),
		dataset("Prophets", db.ProphetCount(), 25, db.GetSetting("prophets_version"), prophetsVersion),
	}

	msg := r.URL.Query().Get("msg")
	errMsg := r.URL.Query().Get("error")

	renderTemplate(w, r, "admin.html", map[string]interface{}{
		"Accounts":     accounts,
		"Users":        users,
		"Integrations": integrations,
		"Tools":        toolDefs,
		"Datasets":     datasets,
		"TaskStats":    taskStats,
		"EmailStats":   emailStats,
		"RecentEmails": recentEmails,
		"RecentTasks":  recentTasks,
		"CurrentUser":  session.Email,
		"Message":      msg,
		"Error":        errMsg,
	})
}

func dataset(name string, got, want int, loadedVer, wantVer string) map[string]interface{} {
	ok := got == want && loadedVer == wantVer
	status := "ok"
	if loadedVer == "" || got == 0 {
		status = "not loaded"
	} else if loadedVer != wantVer {
		status = "stale (loading)"
	} else if got != want {
		status = "partial"
	}
	return map[string]interface{}{
		"Name":          name,
		"Count":         got,
		"Expected":      want,
		"LoadedVersion": loadedVer,
		"WantVersion":   wantVer,
		"OK":            ok,
		"Status":        status,
	}
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

	// Verify ownership; orphans are admin-only and get adopted on toggle.
	userID := getUserID(r)
	ownerID := db.GetConversationOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
		jsonError(w, "Access denied", 403)
		return
	}
	db.AdoptOrphanConversation(req.ID, userID)

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

	// Verify ownership; orphans are admin-only and get adopted on toggle.
	userID := getUserID(r)
	ownerID := db.GetNoteOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
		jsonError(w, "Access denied", 403)
		return
	}
	db.AdoptOrphanNote(req.ID, userID)

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
	showAll := r.URL.Query().Get("show") == "all"
	items, err := db.GetNoteItems(userID, !showAll, isAdminReq(r))
	if err != nil {
		http.Error(w, "Failed to get note items", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, r, "notes.html", map[string]interface{}{
		"Items":         items,
		"CurrentUserID": userID,
		"ShowAll":       showAll,
	})
}

func handleNoteView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/notes/")
	if strings.Contains(idStr, "/") || idStr == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetNoteItem(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	userID := getUserID(r)
	isAdmin := isAdminReq(r)
	isOwner := userID != 0 && item.UserID == userID
	// Access: owner, public, or admin. Orphaned notes (UserID == 0) are admin-only.
	if !isOwner && !item.Public && !isAdmin {
		http.NotFound(w, r)
		return
	}

	renderTemplate(w, r, "notes_view.html", map[string]interface{}{
		"Item":    item,
		"IsOwner": isOwner || isAdmin,
	})
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

	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/notes"
	}
	http.Redirect(w, r, referer, http.StatusSeeOther)
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
	// Orphans (ownerID == 0) are only writable by admins; an admin edit adopts the note.
	isOwner := userID != 0 && ownerID == userID

	if r.Method == "POST" {
		if !isOwner && !isAdmin {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		title := strings.TrimSpace(r.FormValue("title"))
		content := strings.TrimSpace(r.FormValue("content"))

		db.AdoptOrphanNote(id, userID)
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

	// Verify ownership: owner or admin. Orphans are admin-only.
	userID := getUserID(r)
	ownerID := db.GetNoteOwner(id)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdmin(session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	db.DeleteNoteItem(id)
	http.Redirect(w, r, "/notes?msg=Item+deleted", http.StatusSeeOther)
}
