package server

import (
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"strings"

	"aslam/db"
)

//go:embed html/*
var templates embed.FS

func renderTemplate(w http.ResponseWriter, r *http.Request, name string, data map[string]interface{}) {
	if data == nil {
		data = map[string]interface{}{}
	}
	session := getSession(r)
	if session != nil {
		data["IsAdmin"] = db.IsAdmin(session.Email)
	}
	// Templates branch on this to hide account-only affordances (Save, Chat,
	// the nav) from anonymous visitors on public content pages.
	if _, set := data["LoggedIn"]; !set {
		data["LoggedIn"] = isLoggedIn(r)
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

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ghazaliParagraphs preserves paragraph boundaries and escapes all source text.
func ghazaliParagraphs(s string) template.HTML {
	var out strings.Builder
	for _, paragraph := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n\n") {
		p := strings.Join(strings.Fields(paragraph), " ")
		if p == "" {
			continue
		}
		tag := "p"
		switch p {
		case "ACQUISITION OF KNOWLEDGE", "SECTION 1 - EXCELLENCE OF LEARNING":
			tag = "h3"
		case "PROOF OF THE QURAN", "HADIS":
			tag = "h4"
		}
		out.WriteString("<" + tag + ">" + template.HTMLEscapeString(p) + "</" + tag + ">")
	}
	return template.HTML(out.String())
}
