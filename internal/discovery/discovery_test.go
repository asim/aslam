package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryRoutes(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	for path, contentType := range map[string]string{
		"/.well-known/api-catalog": "application/linkset+json",
		"/openapi.json":            "application/json",
		"/llms.txt":                "text/plain",
	} {
		for _, method := range []string{"GET", "HEAD", "POST"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(method, path, nil))
			if method == "POST" {
				if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
					t.Fatalf("%s POST: %d", path, w.Code)
				}
				continue
			}
			if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), contentType) ||
				!strings.Contains(w.Header().Get("Link"), `rel="api-catalog"`) {
				t.Fatalf("%s %s: %d %v", method, path, w.Code, w.Header())
			}
			if method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
			if method == "GET" && (w.Body.Len() == 0 || (path != "/llms.txt" && !json.Valid(w.Body.Bytes()))) {
				t.Fatalf("invalid document: %s", path)
			}
		}
	}
}
