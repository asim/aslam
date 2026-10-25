package server

import (
	"aslam/db"
	"aslam/internal/arabiclearning"
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestArabicLearningPages(t *testing.T) {
	old := tmpl
	defer func() { tmpl = old }()
	var err error
	tmpl, err = template.New("").Parse(`{{define "style"}}{{end}}{{define "header"}}{{end}}`)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err = tmpl.ParseFiles("html/arabic_learning.html")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASLAM_KEY", "arabic-test")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err = db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.DB.Exec("INSERT INTO users(email,name,role) VALUES('learn@test','Learner','user')"); err != nil {
		t.Fatal(err)
	}
	token, err := db.CreateSession("learn@test", "Learner")
	if err != nil {
		t.Fatal(err)
	}
	b, err := arabiclearning.Load()
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{"/arabic/sentences", "/arabic/roots"}
	for _, s := range b.Sentences {
		paths = append(paths, "/arabic/sentences/"+s.Slug)
	}
	for _, root := range b.Roots {
		paths = append(paths, "/arabic/roots/"+root.Slug)
	}
	for _, path := range paths {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: token})
		w := httptest.NewRecorder()
		handleArabicView(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Count(path, "/") == 3 {
			saved, _ := db.GetReadingProgressContext(r.Context(), getUserID(r), "arabic")
			if saved != path {
				t.Fatalf("progress %s != %s", saved, path)
			}
			for _, want := range []string{"/notes/add", "/chat/new"} {
				if !strings.Contains(w.Body.String(), want) {
					t.Fatalf("missing %s", want)
				}
			}
		}
	}
	for _, path := range []string{"/arabic/roots/nope", "/arabic/sentences/", "/arabic/roots/ktb/extra"} {
		w := httptest.NewRecorder()
		handleArabicView(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	var out bytes.Buffer
	err = tmpl.ExecuteTemplate(&out, "arabic_learning.html", map[string]interface{}{"Title": "Example", "Section": "sentences", "Sentence": b.Sentences[0]})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `action="/notes/add"`) {
		t.Fatal("anonymous save form")
	}
}
