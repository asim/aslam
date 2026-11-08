package server

import (
	"aslam/db"
	"net/http"
	"net/http/httptest"
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
