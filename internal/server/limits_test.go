package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrawlerAdmissionAndRecovery(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	h := requestLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/memory" {
			w.WriteHeader(200)
			return
		}
		entered <- struct{}{}
		<-release
	}))
	done := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		go func() {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/quran/1/1", nil))
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("request did not enter")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/hadith/1", nil))
	if w.Code != 503 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("overload: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/memory", nil))
	if w.Code != 200 {
		t.Fatal("crawler blocked admin")
	}
	close(release)
	for i := 0; i < 8; i++ {
		<-done
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/quran/1/1", nil))
	if w.Code != 200 {
		t.Fatal("slot not released")
	}
}

func TestSearchAdmissionAndCancellation(t *testing.T) {
	entered := make(chan struct{}, 2)
	done := make(chan struct{}, 2)
	h := requestLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, path := range []string{"/search?q=mercy", "/api/knowledge/search?q=mercy"} {
		go func(path string) {
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil).WithContext(ctx))
			done <- struct{}{}
		}(path)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("search did not enter")
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/api/search?q=mercy", nil))
	if w.Code != 503 {
		t.Fatalf("third search status %d", w.Code)
	}
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cancellation not propagated")
		}
	}
}

func TestRequestBoundsAndStreaming(t *testing.T) {
	h := requestLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Error("no deadline")
		}
		remaining := time.Until(deadline)
		if r.URL.Path == "/api/chat/send" {
			if remaining < 4*time.Minute {
				t.Error("chat inherited short page deadline")
			}
			f, ok := w.(http.Flusher)
			if !ok {
				t.Error("streaming lost")
				return
			}
			f.Flush()
		} else if remaining > 15*time.Second {
			t.Error("page deadline too long")
		}
		if r.Method == "POST" {
			if _, err := io.ReadAll(r.Body); err == nil {
				t.Error("oversized body accepted")
			}
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/chat/send", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/auth/signup", strings.NewReader(strings.Repeat("x", (1<<20)+1))))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/search?q="+strings.Repeat("x", 1001), nil))
	if w.Code != 400 {
		t.Fatal("oversized query accepted")
	}
}

func TestHostValidationBeforeHandlers(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := restrictHosts(next, "")
	for _, host := range []string{"beal-holdings.co.uk", "www.beal-holdings.co.uk", "aslam.org.evil.test", "", "aslam.org@evil.test"} {
		called = false
		r := httptest.NewRequest("GET", "/hadith/1084", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if called || w.Code != 421 {
			t.Fatalf("accepted foreign host %q: %d", host, w.Code)
		}
	}
	for _, host := range []string{"aslam.org", "www.aslam.org", "ASLAM.ORG:443", "aslam.org.", "localhost:8000", "127.0.0.1:8000", "[::1]:8000"} {
		called = false
		r := httptest.NewRequest("GET", "/hadith/1084", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !called || w.Code != 200 {
			t.Fatalf("rejected valid host %q", host)
		}
	}
	called = false
	r := httptest.NewRequest("GET", "http://reader.example/", nil)
	restrictHosts(next, "reader.example").ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("custom host rejected")
	}
}
