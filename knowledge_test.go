package main

import (
	"aslam/db"
	"aslam/seerah"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestKnowledgeSearchAndCompleteResource(t *testing.T) {
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
	w := httptest.NewRecorder()
	handleKnowledgeSearch(w, httptest.NewRequest("GET", "/api/knowledge/search?q=patience&collection=quran", nil))
	var result struct {
		Results []map[string]interface{} `json:"results"`
	}
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 1 || result.Results[0]["Kind"] != "quran" || result.Results[0]["Source"] != "Quran" {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	handleKnowledgeSearch(w, httptest.NewRequest("GET", "/api/knowledge/search?q=patience", nil))
	if strings.Contains(w.Body.String(), `"Kind":"notes"`) || strings.Contains(w.Body.String(), `"Kind":"chat"`) {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/knowledge/resource?path=/quran/2/153", nil))
	var resource struct {
		Resource map[string]interface{} `json:"resource"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || resource.Resource["Text"] != text || resource.Resource["Arabic"] != "عربي" {
		t.Fatal(w.Body.String())
	}
}

func TestKnowledgeResourceBoundary(t *testing.T) {
	for _, path := range []string{"/notes/1", "/chat/1", "https://other.test/quran/2/1", "/quran/2/1/extra"} {
		w := httptest.NewRecorder()
		handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/knowledge/resource?path="+path, nil))
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
	handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/knowledge/resource?path=/seerah/page/10", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Translator") || !strings.Contains(w.Body.String(), "The Sealed Nectar") {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/knowledge/resource?path=/seerah/page/999", nil))
	if w.Code != 404 {
		t.Fatal(w.Code)
	}
	for _, q := range []string{"collection=notes", "limit=-1", "limit=51", "limit=invalid"} {
		w = httptest.NewRecorder()
		handleKnowledgeSearch(w, httptest.NewRequest("GET", "/api/knowledge/search?"+q, nil))
		if w.Code != 400 {
			t.Fatal(q, w.Code)
		}
	}
}
