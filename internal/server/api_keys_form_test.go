package server

import (
	"aslam/db"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestAPIKeyBrowserForms(t *testing.T) {
	for _, tc := range []struct {
		name, host, origin, site string
		allowed                  bool
	}{
		{"browser", "aslam.org", "https://aslam.org", "same-origin", true},
		{"proxy host", "127.0.0.1:8080", "https://aslam.org", "same-origin", true},
		{"no origin", "aslam.org", "", "same-origin", true},
		{"legacy browser", "aslam.org", "https://aslam.org", "", true},
		{"cross site", "aslam.org", "https://evil.example", "cross-site", false},
		{"same site subdomain", "aslam.org", "https://other.aslam.org", "same-site", false},
		{"legacy cross origin", "aslam.org", "https://evil.example", "", false},
		{"missing headers", "aslam.org", "", "", false},
		{"null origin", "aslam.org", "null", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := modelTestContext(t)
			old := tmpl
			t.Cleanup(func() { tmpl = old })
			tmpl = template.Must(template.New("").Parse(`{{define "style"}}{{end}}{{define "header"}}{{end}}`))
			tmpl = template.Must(tmpl.ParseFiles("html/api_keys.html"))
			session, err := db.CreateSession("test@example.com", "Reader")
			if err != nil {
				t.Fatal(err)
			}
			post := func(form url.Values) *httptest.ResponseRecorder {
				r := httptest.NewRequest("POST", "http://"+tc.host+"/profile/api-keys", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("Origin", tc.origin)
				r.Header.Set("Sec-Fetch-Site", tc.site)
				r.AddCookie(&http.Cookie{Name: "session", Value: session})
				w := httptest.NewRecorder()
				handleAPIKeys(w, r)
				return w
			}
			w := post(url.Values{"name": {"Browser key"}})
			want := http.StatusForbidden
			if tc.allowed {
				want = http.StatusOK
			}
			if w.Code != want {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			keys, err := db.ListAPIKeys(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			if tc.allowed {
				if len(keys) != 1 {
					t.Fatalf("created %d keys", len(keys))
				}
			} else {
				if len(keys) != 0 {
					t.Fatal("rejected form created a key")
				}
				if _, err := db.CreateAPIKey(ctx, 1, "Existing key"); err != nil {
					t.Fatal(err)
				}
				keys, err = db.ListAPIKeys(ctx, 1)
				if err != nil {
					t.Fatal(err)
				}
			}
			w = post(url.Values{"action": {"revoke"}, "id": {strconv.FormatInt(keys[0].ID, 10)}})
			want = http.StatusForbidden
			if tc.allowed {
				want = http.StatusSeeOther
			}
			if w.Code != want {
				t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
			}
			keys, err = db.ListAPIKeys(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			remaining := 1
			if tc.allowed {
				remaining = 0
			}
			if len(keys) != remaining {
				t.Fatalf("remaining keys = %d, want %d", len(keys), remaining)
			}
		})
	}
}
