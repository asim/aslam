package server

import (
	"aslam/db"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionReuseIsRequestScoped(t *testing.T) {
	modelTestContext(t)
	token, err := db.CreateSession("test@example.com", "Reader")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := requestLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		first := getSession(r)
		if calls == 1 {
			if first == nil {
				t.Fatal("missing session")
			}
			if _, err := db.DB.Exec("DELETE FROM sessions WHERE token=?", token); err != nil {
				t.Fatal(err)
			}
			if getSession(r) != first {
				t.Fatal("repeated lookup did not reuse request session")
			}
		} else if first != nil {
			t.Fatal("revoked session leaked into another request")
		}
	}))
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/profile", nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: token})
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
}

// Force different accounts through one physical SQLite connection. Authorization
// must follow each request's credentials, never the connection or prior request.
func TestReusedConnectionKeepsAccountsIsolated(t *testing.T) {
	ctx := modelTestContext(t)
	db.DB.SetMaxOpenConns(1)
	db.DB.SetMaxIdleConns(1)
	if _, err := db.DB.Exec(`INSERT INTO users(id,email,verified,role) VALUES(2,'other@example.com',1,'user');
 INSERT INTO notes_v2(user_id,title,content) VALUES(1,'first-private','one'),(2,'second-private','two')`); err != nil {
		t.Fatal(err)
	}
	first, err := db.CreateSession("test@example.com", "First")
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.CreateSession("other@example.com", "Second")
	if err != nil {
		t.Fatal(err)
	}
	key, err := db.CreateAPIKey(ctx, 2, "test")
	if err != nil {
		t.Fatal(err)
	}
	h := requestLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Even a pre-existing browser lookup cannot override a valid Bearer identity.
		getSession(r)
		requireAuth(handleAPINotes)(w, r)
	}))
	invoke := func(cookie, bearer string, want int, visible, hidden string) {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/notes", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "session", Value: cookie})
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("status=%d, want=%d", w.Code, want)
		}
		body := w.Body.String()
		if visible != "" && !strings.Contains(body, visible) {
			t.Fatal("owner's note missing")
		}
		if hidden != "" && strings.Contains(body, hidden) {
			t.Fatal("another account's note leaked")
		}
	}
	for i := 0; i < 3; i++ {
		invoke(first, "", 200, "first-private", "second-private")
		invoke(second, "", 200, "second-private", "first-private")
		invoke("", "", 401, "", "private")
	}
	invoke(first, key, 200, "second-private", "first-private")
	invoke(first, "invalid", 401, "", "private")
	keys, err := db.ListAPIKeys(ctx, 2)
	if err != nil || len(keys) != 1 {
		t.Fatal("missing test key", err)
	}
	if err := db.RevokeAPIKey(ctx, 2, keys[0].ID); err != nil {
		t.Fatal(err)
	}
	invoke(first, key, 401, "", "private")
	if _, err := db.DB.Exec("UPDATE users SET verified=0 WHERE id=2"); err != nil {
		t.Fatal(err)
	}
	invoke(second, "", 401, "", "private")
	if _, err := db.DB.Exec("UPDATE sessions SET expires_at='2000-01-01' WHERE token=?", first); err != nil {
		t.Fatal(err)
	}
	invoke(first, "", 401, "", "private")
	if stats := db.DB.Stats(); stats.OpenConnections != 1 || stats.MaxIdleClosed != 0 {
		t.Fatalf("connection was not reused: %+v", stats)
	}
}
