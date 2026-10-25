package server

import (
	"archive/zip"
	"aslam/data"
	"aslam/db"
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestArabicSourceLearning(t *testing.T) {
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
	// Simulate a saved vocabulary URL from v1, with an arbitrary pre-existing ID.
	z, err := zip.NewReader(bytes.NewReader(data.Arabic), int64(len(data.Arabic)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := z.Open("arabic_vocab.json")
	if err != nil {
		t.Fatal(err)
	}
	var words []db.ArabicVocabulary
	err = json.NewDecoder(f).Decode(&words)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	first := words[0]
	if _, err = db.DB.Exec(`INSERT INTO arabic(id,arabic,transliteration,english,frequency,example_ref,type) VALUES(90000,?,?,?,?,?,?)`, first.Arabic, first.Transliteration, first.English, first.Frequency, first.ExampleRef, first.Type); err != nil {
		t.Fatal(err)
	}
	loadArabic()
	if db.GetSetting("arabic_version") != arabicVersion {
		t.Fatal("import did not commit")
	}
	if db.ArabicCount() != 21247 {
		t.Fatal(db.ArabicCount())
	}
	saved, err := db.GetArabicWord(90000)
	if err != nil || saved["Arabic"] != first.Arabic {
		t.Fatal("saved word ID changed", err)
	}
	loadArabic()
	if db.ArabicCount() != 21247 {
		t.Fatal("duplicate import")
	}
	if _, err = db.DB.Exec("INSERT INTO users(email,name,role) VALUES('learn@test','Learner','user')"); err != nil {
		t.Fatal(err)
	}
	token, err := db.CreateSession("learn@test", "Learner")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/arabic/roots", "/arabic/roots?q=k-t-b", "/arabic/roots?offset=50", "/arabic/roots/ktb", "/arabic/roots/ktb?offset=50", "/arabic/reading", "/arabic/reading?level=medium", "/arabic/reading?level=long", "/arabic/reading/1/1"} {
		r := httptest.NewRequest("GET", path, nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: token})
		w := httptest.NewRecorder()
		handleArabicView(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if r.URL.Path == "/arabic/roots/ktb" {
			if !strings.Contains(w.Body.String(), "كتب") || !strings.Contains(w.Body.String(), `href="/arabic/`) {
				t.Fatal("missing root vocabulary")
			}
			progress, _ := db.GetReadingProgressContext(r.Context(), getUserID(r), "arabic")
			if progress != path {
				t.Fatalf("progress=%s expected=%s", progress, path)
			}
		}
	}
	r := httptest.NewRequest("GET", "/arabic/reading/1/1", nil)
	p, err := db.ArabicPassageContext(r.Context(), 1, 1)
	if err != nil || len(p.Words) != 4 || p.Words[0].VocabularyID == 0 {
		t.Fatalf("passage link: %+v %v", p, err)
	}
	linked, err := db.GetArabicWord(p.Words[0].VocabularyID)
	if err != nil || linked["Arabic"] != p.Words[0].Arabic {
		t.Fatal("incorrect vocabulary link", err)
	}
	roots, err := db.ArabicRootsContext(r.Context(), "ktb", 0)
	if err != nil || len(roots) != 1 || roots[0].Arabic != "كتب" || roots[0].Count < 50 {
		t.Fatalf("roots %+v %v", roots, err)
	}
	for _, path := range []string{"/arabic/roots/nope", "/arabic/reading/", "/arabic/reading/999/1", "/arabic/reading/1/1/extra"} {
		w := httptest.NewRecorder()
		handleArabicView(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal(path, w.Code)
		}
	}
	for _, path := range []string{"/arabic/reading?level=nope", "/arabic/roots?offset=-1", "/arabic/roots?offset=x"} {
		w := httptest.NewRecorder()
		handleArabicView(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
}
