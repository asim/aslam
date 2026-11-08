package server

import (
	"aslam/db"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPKnowledgeTools(t *testing.T) {
	t.Setenv("ASLAM_KEY", "mcp-test")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.DB.Exec("INSERT INTO quran(chapter,chapter_name,verse,text,arabic,commentary) VALUES(2,'Al-Baqarah',153,'patience','عربي','commentary')"); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ASLAM_ALLOWED_HOSTS", "127.0.0.1")
	srv := httptest.NewServer(requestLimits(newMCPHandler()))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Tools) != 5 {
		t.Fatalf("tools: %+v", list.Tools)
	}
	for _, tool := range list.Tools {
		if !tool.Annotations.ReadOnlyHint {
			t.Fatal("missing read-only annotation")
		}
	}
	for _, tc := range []struct {
		name    string
		args    map[string]any
		isError bool
	}{
		{"search", map[string]any{"q": ""}, false},
		{"search", map[string]any{"q": "patience", "collection": "quran"}, false},
		{"read", map[string]any{"path": "/quran/2/153"}, false},
		{"search", map[string]any{"q": "x", "collection": "notes"}, true},
		{"search", map[string]any{"q": strings.Repeat("a", 1001)}, true},
		{"search", map[string]any{"q": "x", "limit": 51}, true},
		{"read", map[string]any{"path": "/notes/1"}, true},
		{"read", map[string]any{"path": "/chat/1"}, true},
		{"read", map[string]any{"path": "https://example.com"}, true},
	} {
		result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tc.name, Arguments: tc.args})
		if err != nil {
			t.Fatal(err)
		}
		if !tc.isError && tc.name == "read" {
			text := result.Content[0].(*mcp.TextContent).Text
			if !strings.Contains(text, "patience") || !strings.Contains(text, "https://aslam.org/quran/2/153") {
				t.Fatalf("missing passage or citation: %s", text)
			}
		}
		if result.IsError != tc.isError {
			t.Fatalf("%s %+v: %+v", tc.name, tc.args, result)
		}
	}
}

func TestMCPHTTPGuards(t *testing.T) {
	t.Setenv("ASLAM_ALLOWED_HOSTS", "aslam.org")
	handler := newMCPHandler()
	for _, tc := range []struct {
		method, host, origin, body string
		want                       int
	}{
		{"GET", "aslam.org", "", "", 405},
		{"POST", "attacker.test", "", "{}", 421},
		{"POST", "aslam.org", "https://attacker.test", "{}", 403},
		{"POST", "aslam.org", "", strings.Repeat(" ", 17000), 413},
	} {
		r := httptest.NewRequest(tc.method, "https://"+tc.host+"/mcp", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s %s: %d %s", tc.method, tc.host, w.Code, w.Body.String())
		}
	}
}

func TestMCPAdapterPreservesContextAndErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := mcpKnowledge(ctx, func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Err() == nil {
			t.Error("cancellation lost")
		}
		if len(r.Header) != 0 {
			t.Error("credentials forwarded")
		}
		http.Error(w, "unavailable", 503)
	}, nil)
	if !result.IsError {
		t.Fatal("HTTP error reported as success")
	}
}
