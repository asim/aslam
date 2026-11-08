package server

import (
	"aslam/data"
	"aslam/db"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTafsirReaderAndAPI(t *testing.T) {
	modelTestContext(t)
	if err := db.ImportTafsir(data.Tafsir); err != nil {
		t.Fatal(err)
	}
	old := tmpl
	defer func() { tmpl = old }()
	tmpl = template.Must(template.New("").Parse(`{{define "style"}}{{end}}{{define "header"}}{{end}}`))
	tmpl = template.Must(tmpl.ParseFiles("html/tafsir.html", "html/tafsir_index.html"))
	token, err := db.CreateSession("test@example.com", "Reader")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/tafsir", "/tafsir/ibn-kathir/2?limit=2", "/tafsir/ibn-kathir/73/1"} {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: token})
		w := httptest.NewRecorder()
		handleTafsir(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	path, _ := db.GetReadingProgress(1, "tafsir")
	if path != "/tafsir/ibn-kathir/73/1" {
		t.Fatal("progress", path)
	}
	w := httptest.NewRecorder()
	handleTafsir(w, httptest.NewRequest("GET", "/tafsir/ibn-kathir/73/4", nil))
	if w.Code != 302 || w.Header().Get("Location") != "/tafsir/ibn-kathir/73/1" {
		t.Fatal(w.Code, w.Header())
	}
	w = httptest.NewRecorder()
	handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/knowledge/resource?path=/tafsir/ibn-kathir/73/4", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "73/1") || !strings.Contains(w.Body.String(), "Ayahs") {
		t.Fatal(w.Code, w.Body.String())
	}
}
