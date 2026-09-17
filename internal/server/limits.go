package server

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"
)

// Separate pools keep public crawling from consuming every application slot.
// Admission never waits: a queue here would retain request goroutines and data.
func limitConcurrency(next http.Handler, slots chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			next.ServeHTTP(w, r)
		default:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Server busy; please retry shortly", http.StatusServiceUnavailable)
		}
	})
}

func isPublicContent(path string) bool {
	for _, root := range []string{"/search", "/api/search", "/api/knowledge", "/api/arabic/search", "/quran", "/hadith", "/names", "/islamqa", "/ghazali", "/adhkar", "/salihin", "/arabic", "/stories", "/seerah"} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

func requestLimits(next http.Handler) http.Handler {
	public := limitConcurrency(next, make(chan struct{}, 8))
	other := limitConcurrency(next, make(chan struct{}, 16))
	searches := limitConcurrency(public, make(chan struct{}, 2))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bound bodies before ParseForm/JSON decoding; headers have a separate cap.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		timeout := 15 * time.Second
		if r.URL.Path == "/api/chat/send" || r.URL.Path == "/chat/send" {
			timeout = 5 * time.Minute
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		r = r.WithContext(ctx)
		// Set a finite socket deadline without wrapping the writer: streaming retains
		// http.Flusher support. Chat receives a longer, still bounded deadline.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
		if r.URL.Path == "/arabic" && r.URL.Query().Get("q") != "" {
			if len(r.URL.Query().Get("q")) > 1000 {
				http.Error(w, "Query is too long", http.StatusBadRequest)
				return
			}
			searches.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/search", "/api/search", "/api/knowledge/search", "/api/arabic/search":
			if len(r.URL.Query().Get("q")) > 1000 {
				http.Error(w, "Query is too long", http.StatusBadRequest)
				return
			}
			searches.ServeHTTP(w, r)
		default:
			if isPublicContent(r.URL.Path) {
				public.ServeHTTP(w, r)
			} else {
				other.ServeHTTP(w, r)
			}
		}
	})
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: restrictHosts(requestLimits(handler), os.Getenv("ASLAM_ALLOWED_HOSTS")),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}
