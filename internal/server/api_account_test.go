package server

import (
	"aslam/db"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountAPIKeysAndIsolation(t *testing.T) {
	ctx := modelTestContext(t)
	if _, err := db.DB.Exec("INSERT INTO users(id,email,verified,role) VALUES(2,'other@example.com',1,'user'); INSERT INTO conversations(id,title,user_id) VALUES(2,'private',2); INSERT INTO messages(conversation_id,role,content) VALUES(2,'user','secret')"); err != nil {
		t.Fatal(err)
	}
	key, err := db.CreateAPIKey(ctx, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := db.ListAPIKeys(ctx, 1)
	if err != nil || len(keys) != 1 {
		t.Fatal(keys, err)
	}
	var stored string
	db.DB.QueryRow("SELECT hash FROM api_keys WHERE id=?", keys[0].ID).Scan(&stored)
	if stored == key || len(stored) != 64 {
		t.Fatal("raw key stored")
	}
	invoke := func(method, path, body, token string, h http.HandlerFunc) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		requireAuth(h)(w, r)
		return w
	}
	if w := invoke("GET", "/api/profile", "", "", handleAPIProfile); w.Code != 401 {
		t.Fatalf("anonymous bypass: %d", w.Code)
	}
	if w := invoke("GET", "/api/profile", "", key, handleAPIProfile); w.Code != 200 || !strings.Contains(w.Body.String(), "test@example.com") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := invoke("GET", "/api/chat/latest?id=2", "", key, handleAPIChatLatest); w.Code != 404 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("private chat leaked", w.Code, w.Body.String())
	}
	w := invoke("POST", "/api/notes", `{"title":"mine","content":"private"}`, key, handleAPINotes)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	other, err := db.CreateAPIKey(ctx, 2, "other")
	if err != nil {
		t.Fatal(err)
	}
	if w := invoke("GET", "/api/notes/1", "", other, handleAPINotes); w.Code != 404 {
		t.Fatal("note read leaked", w.Code)
	}
	if w := invoke("DELETE", "/api/notes/1", "", other, handleAPINotes); w.Code != 404 {
		t.Fatal("note delete leaked", w.Code)
	}
	if w := invoke("GET", "/api/notes/1", "", key, handleAPINotes); w.Code != 200 {
		t.Fatal("owner cannot read note", w.Code)
	}
	if err := db.RevokeAPIKey(ctx, 2, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.APIKeySession(ctx, key); err != nil {
		t.Fatal("other user revoked key")
	}
	if err := db.RevokeAPIKey(ctx, 1, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	if w := invoke("GET", "/api/profile", "", key, handleAPIProfile); w.Code != 401 {
		t.Fatal("revoked key accepted")
	}
	if _, err := db.DB.Exec("UPDATE users SET verified=0 WHERE id=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.APIKeySession(ctx, other); err == nil {
		t.Fatal("unverified key accepted")
	}
}

func TestAllKnowledgeCollectionsBrowse(t *testing.T) {
	modelTestContext(t)
	for kind := range knowledgeCollections {
		if kind == "seerah" {
			continue
		}
		w := httptest.NewRecorder()
		handleKnowledgeBrowse(w, httptest.NewRequest("GET", "/api/knowledge/browse?collection="+kind, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", kind, w.Code, w.Body.String())
		}
	}
	if _, err := db.DB.Exec("INSERT INTO quran(chapter,chapter_name,verse,text) VALUES(1,'Opening',1,'one'),(1,'Opening',2,'two')"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleKnowledgeBrowse(w, httptest.NewRequest("GET", "/api/knowledge/browse?collection=quran&limit=1", nil))
	var page struct {
		Results []map[string]any
		Next    string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Results) != 1 || page.Next == "" {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	handleKnowledgeBrowse(w, httptest.NewRequest("GET", page.Next, nil))
	if !strings.Contains(w.Body.String(), "/quran/1/2") {
		t.Fatal(w.Body.String())
	}
}

func TestMCPRequiresAccountKey(t *testing.T) {
	ctx := modelTestContext(t)
	t.Setenv("ASLAM_ALLOWED_HOSTS", "aslam.org")
	key, err := db.CreateAPIKey(ctx, 1, "agent")
	if err != nil {
		t.Fatal(err)
	}
	h := accountAPI(newMCPHandler(), true)
	for _, token := range []string{"", key} {
		r := httptest.NewRequest("POST", "https://aslam.org/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		want := 401
		if token != "" {
			want = 200
		}
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestExpandedKnowledgeResources(t *testing.T) {
	modelTestContext(t)
	for _, q := range []string{
		`INSERT INTO arabic(id,arabic,english,transliteration) VALUES(1,'كتاب','book','kitab')`,
		`INSERT INTO arabic_roots(word_id,code,arabic,lemma,type) VALUES(1,'ktb','كتب','kitab','noun')`,
		`INSERT INTO arabic_passages(chapter,verse,title,arabic,english,word_count,words) VALUES(1,1,'Opening','عربي','In the name',3,'[]')`,
		`INSERT INTO prophets(slug,name,title,summary,verses) VALUES('adam','Adam','Prophet','story','[]')`,
	} {
		if _, err := db.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"/arabic/1", "/arabic/roots/ktb", "/arabic/reading/1/1", "/stories/adam"} {
		w := httptest.NewRecorder()
		handleKnowledgeResource(w, httptest.NewRequest("GET", "/api/knowledge/resource?path="+path, nil))
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for _, kind := range []string{"arabic", "roots", "reading", "stories"} {
		w := httptest.NewRecorder()
		handleKnowledgeSearch(w, httptest.NewRequest("GET", "/api/knowledge/search?collection="+kind+"&q=a", nil))
		if w.Code != 200 {
			t.Fatal(kind, w.Code, w.Body.String())
		}
	}
}
