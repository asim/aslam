package server

import (
	"aslam/db"
	"aslam/internal/seerah"
	"bytes"
	"html/template"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStaticAssetValidation(t *testing.T) {
	handler := handleStatic("app.css", "text/css")
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest("GET", "/app.css?v="+buildVersion, nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatal(w.Code, w.Header())
	}
	r := httptest.NewRequest("GET", "/app.css", nil)
	r.Header.Set("If-None-Match", w.Header().Get("ETag"))
	cached := httptest.NewRecorder()
	handler(cached, r)
	if cached.Code != 304 || cached.Body.Len() != 0 {
		t.Fatal(cached.Code)
	}
	sw := httptest.NewRecorder()
	handleStatic("sw.js", "application/javascript")(sw, httptest.NewRequest("GET", "/sw.js?v="+buildVersion, nil))
	if strings.Contains(sw.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("cached service worker indefinitely")
	}
}

func TestReaderTemplates(t *testing.T) {
	funcs := template.FuncMap{"version": func() string { return "test" }, "hasPrefix": strings.HasPrefix, "formatTime": func(t time.Time) string { return t.Format("2006-01-02") }, "truncate": truncateRunes, "ghazaliParagraphs": ghazaliParagraphs, "paragraphs": ghazaliParagraphs, "lines": ghazaliParagraphs}
	tpl, err := template.New("").Funcs(funcs).ParseFS(templates, "html/*.html")
	if err != nil {
		t.Fatal(err)
	}
	chapters, err := quranChapters()
	if err != nil {
		t.Fatal(err)
	}
	if len(chapters) != 114 || chapters[0]["Arabic"] != "الفاتحة" || chapters[0]["Meaning"] != "The Opener" {
		t.Fatal("missing chapter metadata")
	}
	book, err := seerah.Load()
	if err != nil {
		t.Fatal(err)
	}
	headings := 0
	for _, p := range book.Pages {
		for _, b := range p.Blocks {
			if b.Heading {
				headings++
			}
		}
	}
	indexed := 0
	for _, c := range book.Contents {
		indexed += len(c.Sections)
	}
	if headings != indexed {
		t.Fatal("lost section links")
	}
	for name, d := range map[string]map[string]interface{}{
		"quran_index.html":     {"Chapters": chapters, "ContinuePath": "/quran/1/1", "ContinueTitle": "Al-Fatihah"},
		"seerah_index.html":    {"Book": book},
		"arabic_learning.html": {"Title": "Phrases & verses", "Section": "reading", "Level": "short", "ContinuePath": "/arabic/reading/1/1", "ContinueTitle": "Al-Fatihah", "Passages": []db.ArabicPassage{{Chapter: 1, Verse: 1, Title: "Al-Fatihah", Arabic: "بسم الله", English: "In the name of Allah"}}},
		"home.html":            {"LoggedIn": true, "Conversations": []db.Conversation{{ID: 1, Title: "Example question"}}, "RecentNotes": []db.NoteItem{{ID: 1, Title: "Saved reading"}}, "RandomQA": map[string]string{"Question": "A daily question", "Slug": "example"}},
		"chat.html":            {"Conversation": db.Conversation{ID: 1, Title: "Example chat"}, "CanSend": true, "IsOwner": true, "ViewerName": "Reader"},
		"landing.html":         {},
	} {
		var out bytes.Buffer
		if err := tpl.ExecuteTemplate(&out, name, d); err != nil {
			t.Fatal(name, err)
		}
		if name == "chat.html" && (strings.Contains(out.String(), "mic-btn") || strings.Contains(out.String(), "SpeechRecognition")) {
			t.Fatal("microphone still present")
		}
		if name == "seerah_index.html" && strings.Contains(out.String(), "<details") {
			t.Fatal("contents still collapsed")
		}
		if dir := os.Getenv("ASLAM_PREVIEW_DIR"); dir != "" {
			if err := os.WriteFile(filepath.Join(dir, name), out.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
