package server

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"aslam/db"
	"aslam/internal/tools"
)

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

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
		"Memory":       captureMemory(),
		"Users":        users,
		"Integrations": integrations,
		"Tools":        toolDefs,
		"Datasets":     datasets,
		"TaskStats":    taskStats,
		"EmailStats":   emailStats,
		"EmailWorker":  getEmailWorkerStatus(),
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
