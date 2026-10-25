package server

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"

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
		data["IsAdmin"] = db.IsAdminContext(r.Context(), session.Email)
	}
	// Templates branch on this to hide account-only affordances (Save, Chat,
	// the nav) from anonymous visitors on public content pages.
	if _, set := data["LoggedIn"]; !set {
		data["LoggedIn"] = isLoggedIn(r)
	}
	tmpl.ExecuteTemplate(w, name, data)
}

func handleStatic(name, contentType string) http.HandlerFunc {
	content, err := templates.ReadFile("html/" + name)
	etag := fmt.Sprintf("\"%x\"", sha256.Sum256(content))
	return func(w http.ResponseWriter, r *http.Request) {
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
		if buildVersion != "" && r.URL.Query().Get("v") == buildVersion && name != "sw.js" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(content))
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

// Older exports indent hard-wrapped continuation lines. Only join boundaries
// with those local wrapping cues; blank lines elsewhere imply nothing.
var islamQAItem = regexp.MustCompile(`^(?:[0-9]+[.)-]|[-•])(?:\s|$)`)

func islamQAParagraphs(s string) template.HTML {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	var out strings.Builder
	var paragraph []string
	flush := func() {
		if len(paragraph) == 0 {
			return
		}
		out.WriteString("<p>" + template.HTMLEscapeString(strings.Join(paragraph, " ")) + "</p>")
		paragraph = nil
	}
	for i, raw := range lines {
		line := strings.Join(strings.Fields(raw), " ")
		if line == "" {
			flush()
			continue
		}
		wrapped := false
		if i > 0 && len(paragraph) > 0 {
			prev := lines[i-1]
			indented := strings.HasPrefix(raw, "\t") || strings.HasPrefix(raw, "  ")
			// Exported wrapped lines are short and usually retain a trailing space.
			wrapped = indented && len([]rune(strings.TrimSpace(prev))) <= 120 &&
				(strings.HasSuffix(prev, " ") || strings.HasPrefix(prev, "\t") || islamQAItem.MatchString(strings.TrimSpace(prev)))
		}
		if !wrapped || islamQAItem.MatchString(line) {
			flush()
		}
		paragraph = append(paragraph, line)
		if strings.HasSuffix(line, ":") || line == "Praise be to Allah." {
			flush()
		}
	}
	flush()
	return template.HTML(out.String())
}
