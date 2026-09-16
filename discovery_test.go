package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDiscoveryRoutes(t *testing.T) {
	mux := http.NewServeMux()
	registerDiscoveryRoutes(mux)
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

func TestKnowledgeDiscoveryContract(t *testing.T) {
	var spec struct {
		Paths      map[string]json.RawMessage `json:"paths"`
		Security   []json.RawMessage          `json:"security"`
		Components struct {
			Schemas map[string]struct {
				Enum []string `json:"enum"`
			} `json:"schemas"`
		} `json:"components"`
	}
	data, _ := discoveryFiles.ReadFile("discovery/openapi.json")
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Security == nil || len(spec.Security) != 0 {
		t.Fatal("public API must explicitly require no authentication")
	}
	kinds := spec.Components.Schemas["Collection"].Enum
	if len(kinds) != len(knowledgeCollections) {
		t.Fatal("documented collections drifted")
	}
	for _, kind := range kinds {
		if knowledgeCollections[kind] == "" {
			t.Fatalf("unknown documented collection %s", kind)
		}
	}
	handlers := map[string]http.HandlerFunc{
		"/api/knowledge/search":   handleKnowledgeSearch,
		"/api/knowledge/resource": handleKnowledgeResource,
	}
	if len(spec.Paths) != len(handlers) {
		t.Fatal("documented paths drifted")
	}
	var catalog struct {
		Linkset []struct {
			Anchor string `json:"anchor"`
			Items  []struct {
				Href string `json:"href"`
			} `json:"item"`
			Descriptions []struct {
				Href string `json:"href"`
			} `json:"service-desc"`
			Docs []struct {
				Href string `json:"href"`
			} `json:"service-doc"`
		} `json:"linkset"`
	}
	data, _ = discoveryFiles.ReadFile("discovery/api-catalog.json")
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Linkset) != 3 || len(catalog.Linkset[0].Items) != len(handlers) {
		t.Fatal("catalog must enumerate both knowledge endpoints")
	}
	for _, item := range catalog.Linkset[0].Items {
		u, err := url.Parse(item.Href)
		if err != nil || u.Scheme != "https" || u.Host != "aslam.org" || handlers[u.Path] == nil {
			t.Fatalf("invalid catalog endpoint %s", item.Href)
		}
	}
	for _, entry := range catalog.Linkset[1:] {
		if len(entry.Descriptions) != 1 || entry.Descriptions[0].Href != "https://aslam.org/openapi.json" ||
			len(entry.Docs) != 1 || entry.Docs[0].Href != "https://aslam.org/llms.txt" {
			t.Fatal("catalog description links broken")
		}
	}
	for path, handler := range handlers {
		if _, ok := spec.Paths[path]; !ok {
			t.Fatalf("missing endpoint %s", path)
		}
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 405 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("method contract: %s", path)
		}
	}
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/api/knowledge/search", 200},
		{"/api/knowledge/search?collection=notes", 400},
		{"/api/knowledge/search?limit=51", 400},
		{"/api/knowledge/search?limit=0", 400},
		{"/api/knowledge/search?q=" + strings.Repeat("a", 1001), 400},
		{"/api/knowledge/resource?path=/notes/1", 400},
		{"/api/knowledge/resource", 400},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		w := httptest.NewRecorder()
		handlers[r.URL.Path](w, r)
		if w.Code != tc.status || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
}
