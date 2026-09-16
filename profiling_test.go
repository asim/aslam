package main

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"aslam/db"
)

func TestProfilingAdminBoundary(t *testing.T) {
	t.Setenv("ASLAM_KEY", "profiling-test-key")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Even installations without OAuth and API-key bypasses need an admin session.
	oldGoogle, oldKey := googleClientID, apiKey
	googleClientID, apiKey = "", "test-api-key"
	defer func() { googleClientID, apiKey = oldGoogle, oldKey }()
	for _, role := range []string{"user", "admin"} {
		if _, err := db.DB.Exec(`INSERT INTO users(email,name,role,verified) VALUES(?,?,?,1)`, role+"@example.com", role, role); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	registerProfilingRoutes(mux)
	for _, path := range []string{"/admin/memory", "/admin/profile?kind=heap", "/admin/profile?kind=allocs", "/admin/profile?kind=goroutine"} {
		for _, role := range []string{"", "user", "admin"} {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("X-API-Key", apiKey)
			if role != "" {
				token, err := db.CreateSession(role+"@example.com", role)
				if err != nil {
					t.Fatal(err)
				}
				r.AddCookie(&http.Cookie{Name: "session", Value: token})
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			want := map[string]int{"": 303, "user": 403, "admin": 200}[role]
			if w.Code != want {
				t.Fatalf("%s %s: got %d want %d: %s", role, path, w.Code, want, w.Body.String())
			}
			if role != "admin" {
				continue
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("profile must not be cached")
			}
			if path == "/admin/memory" {
				var s memorySnapshot
				if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
					t.Fatal(err)
				}
				if s.Goroutines == 0 || s.HeapAllocBytes == 0 || s.CapturedAt == "" {
					t.Fatalf("invalid snapshot: %+v", s)
				}
			} else {
				gz, err := gzip.NewReader(w.Body)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(gz)
				gz.Close()
				if err != nil || len(data) == 0 {
					t.Fatalf("invalid profile: %v", err)
				}
			}
		}
	}
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal("public profiling route registered")
		}
	}
}

func TestProfileRejectsUnsupportedRequests(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/admin/profile?kind=heap", 405},
		{"GET", "/admin/profile?kind=cpu", 400},
		{"GET", "/admin/profile", 400},
	} {
		w := httptest.NewRecorder()
		handleMemoryProfile(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}
