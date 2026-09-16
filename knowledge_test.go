package main

import (
	"aslam/db"
	"aslam/seerah"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestKnowledgeSearchAndCompleteResource(t *testing.T) {
	mux := http.NewServeMux()
	registerContentAPIRoutes(mux)
	t.Setenv("ASLAM_KEY", "knowledge-test-key")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	text := "patience " + strings.Repeat("complete passage ", 80)
	for _, stmt := range []struct {
		q    string
		args []interface{}
	}{
		{`INSERT INTO quran(chapter,chapter_name,verse,text,arabic,commentary) VALUES(2,'Al-Baqarah',153,?,'عربي','commentary')`, []interface{}{text}},
		{`INSERT INTO notes_v2(title,content,user_id,public) VALUES('patience','personal note',1,1)`, nil},
		{`INSERT INTO conversations(title,user_id,public) VALUES('patience',1,1)`, nil},
	} {
		if _, err := db.DB.Exec(stmt.q, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	// The canonical route must preserve the original handler's response.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/search?q=patience", nil))
	baseline := httptest.NewRecorder()
	optionalAuth(handleAPISearch)(baseline, httptest.NewRequest("GET", "/api/search?q=patience", nil))
	if w.Code != baseline.Code || w.Body.String() != baseline.Body.String() {
		t.Fatal("existing search behavior changed")
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/resource?path=/quran/2/153", nil))
	var resource struct {
		Resource map[string]interface{} `json:"resource"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || resource.Resource["Text"] != text || resource.Resource["Arabic"] != "عربي" {
		t.Fatal(w.Body.String())
	}

	for _, path := range []string{"/api/app/search", "/api/knowledge/search", "/api/knowledge/resource"} {
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatalf("unrequested route still registered: %s", path)
		}
	}

}

func TestKnowledgeResourceBoundary(t *testing.T) {
	for _, path := range []string{"/notes/1", "/chat/1", "https://other.test/quran/2/1", "/quran/2/1/extra"} {
		w := httptest.NewRecorder()
		handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/resource?path="+path, nil))
		if w.Code != 400 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	var err error
	seerahBook, err = seerah.Load()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/resource?path=/seerah/page/10", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Translator") || !strings.Contains(w.Body.String(), "The Sealed Nectar") {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/resource?path=/seerah/page/999", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
}
