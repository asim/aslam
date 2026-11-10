package server

import (
	"aslam/db"
	"aslam/internal/tools"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestToolIdentitiesStayIsolated(t *testing.T) {
	modelTestContext(t)
	if _, err := db.DB.Exec(`INSERT INTO users(id,email,verified,role) VALUES(2,'other@test',1,'user'); INSERT INTO conversations(id,user_id,title) VALUES(2,2,'other')`); err != nil {
		t.Fatal(err)
	}
	tools.SetNoteStorage(&noteStorage{})
	tools.SetStorage(&dbStorage{})
	t.Cleanup(func() { tools.SetNoteStorage(nil); tools.SetStorage(nil) })
	var wg sync.WaitGroup
	for id := int64(1); id <= 2; id++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			ctx, _, err := modelIdentity(context.Background(), id)
			if err != nil {
				t.Error(err)
				return
			}
			for i := 0; i < 4; i++ {
				if _, err := executeChatTool(ctx, "note_add", map[string]interface{}{"title": "owner note", "content": "private"}); err != nil {
					t.Error(err)
				}
			}
		}(id)
	}
	wg.Wait()
	for id := int64(1); id <= 2; id++ {
		var count int
		if err := db.DB.QueryRow("SELECT count(*) FROM notes_v2 WHERE user_id=?", id).Scan(&count); err != nil || count != 4 {
			t.Fatalf("owner=%d count=%d err=%v", id, count, err)
		}
	}
	var otherNote int64
	db.DB.QueryRow("SELECT id FROM notes_v2 WHERE user_id=2 LIMIT 1").Scan(&otherNote)
	ctx, _, err := modelIdentity(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeChatTool(ctx, "note_update", map[string]interface{}{"id": float64(otherNote), "content": "overwritten"}); err == nil {
		t.Fatal("cross-account write allowed")
	}
	if _, err := executeChatTool(ctx, "email_check", nil); err == nil {
		t.Fatal("server mailbox exposed")
	}
	if _, err := executeChatTool(context.Background(), "search_saved", map[string]interface{}{"query": "private"}); err == nil {
		t.Fatal("identity-free recall allowed")
	}
	result, err := executeChatTool(ctx, "search_saved", map[string]interface{}{"query": "private"})
	if err != nil || strings.Count(result, "private") != 4 {
		t.Fatalf("recall crossed identities: %s %v", result, err)
	}
}
func TestAuthenticationFailsClosed(t *testing.T) {
	old := googleClientID
	googleClientID = ""
	t.Cleanup(func() { googleClientID = old })
	called := false
	handler := requireAuth(func(http.ResponseWriter, *http.Request) { called = true })
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest("GET", "/notes?dev=anything&auth=anything", nil))
	if called || w.Code != 303 || len(w.Result().Cookies()) != 0 {
		t.Fatal("unauthenticated bypass")
	}
	w = httptest.NewRecorder()
	handleOAuthCallback(w, httptest.NewRequest("GET", "/auth/callback?state=attacker&code=code", nil))
	if w.Code != 400 {
		t.Fatal("unbound OAuth callback accepted")
	}
}
func TestEmailThreadOwnership(t *testing.T) {
	modelTestContext(t)
	if err := db.CreateEmailThread("private-thread", 1, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := getOrCreateConversation("private-thread", "subject", "other@test"); err == nil {
		t.Fatal("cross-account email thread accepted")
	}
	if id, err := getOrCreateConversation("private-thread", "subject", "test@example.com"); err != nil || id != 1 {
		t.Fatal(id, err)
	}
}
func TestBrowserMutationsRejectCrossOrigin(t *testing.T) {
	called := false
	server := newHTTPServer("", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r := httptest.NewRequest("POST", "https://aslam.org/notes/add", nil)
	r.Header.Set("Origin", "https://attacker.example")
	w := httptest.NewRecorder()
	server.Handler.ServeHTTP(w, r)
	if called || w.Code != 403 {
		t.Fatal("cross-origin mutation accepted", w.Code)
	}
}

func TestSavedSearchNormalizesFTS(t *testing.T) {
	modelTestContext(t)
	if _, err := db.AddNoteItem("prayer", "prayer", 1); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{`prayer "`, `prayer (`, `prayer AND`} {
		results, err := (&dbStorage{}).SearchAll(query, 1)
		if err != nil || len(results) == 0 {
			t.Fatal(query, results, err)
		}
	}
}
