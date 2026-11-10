package server

import (
	"aslam/data"
	"aslam/db"
	"aslam/internal/seerah"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestChatKnowledgeCoverage(t *testing.T) {
	ctx := modelTestContext(t)
	if err := db.ImportTafsir(data.Tafsir); err != nil {
		t.Fatal(err)
	}
	oldBook := seerahBook
	t.Cleanup(func() { seerahBook = oldBook })
	var err error
	seerahBook, err = seerah.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO arabic(id,arabic,english,transliteration) VALUES(1,'كتاب','book','kitab')`,
		`INSERT INTO arabic_roots(word_id,code,arabic,lemma,type) VALUES(1,'ktb','كتب','kitab','noun')`,
		`INSERT INTO arabic_passages(chapter,verse,title,arabic,english,word_count,words) VALUES(1,1,'Opening','عربي','In the name',3,'[]')`,
		`INSERT INTO prophets(slug,name,title,summary,verses) VALUES('adam','Adam','Prophet','story','[]')`,
		`INSERT INTO notes_v2(title,content,user_id,public) VALUES('private sentinel','private sentinel',1,0)`,
	} {
		if _, err := db.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	definitions := map[string]bool{}
	for _, tool := range chatTools() {
		if definitions[tool.Name] {
			t.Fatal("duplicate tool", tool.Name)
		}
		definitions[tool.Name] = true
	}
	for _, name := range []string{"collections", "search", "read", "contents", "browse", "search_saved"} {
		if !definitions[name] {
			t.Fatal("missing tool", name)
		}
	}
	catalog, err := executeChatTool(ctx, "collections", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Every API/MCP collection must also be discoverable and callable from chat.
	for kind := range knowledgeCollections {
		if !strings.Contains(catalog, kind) {
			t.Fatal("missing collection", kind)
		}
		for _, name := range []string{"search", "contents", "browse"} {
			if _, err := executeChatTool(ctx, name, map[string]interface{}{"collection": kind, "q": "mercy", "limit": float64(1)}); err != nil {
				t.Fatalf("%s/%s: %v", kind, name, err)
			}
		}
	}
	for _, tc := range []struct{ kind, q, path string }{
		{"tafsir", "Allah", "/tafsir/ibn-kathir/73/1"},
		{"arabic", "book", "/arabic/1"},
		{"roots", "ktb", "/arabic/roots/ktb"},
		{"reading", "name", "/arabic/reading/1/1"},
		{"stories", "Adam", "/stories/adam"},
	} {
		result, err := executeChatTool(ctx, "search", map[string]interface{}{"collection": tc.kind, "q": tc.q})
		if err != nil {
			t.Fatal(err)
		}
		var found struct {
			Results []map[string]interface{} `json:"results"`
		}
		if err := json.Unmarshal([]byte(result), &found); err != nil || len(found.Results) == 0 {
			t.Fatalf("%s search: %s %v", tc.kind, result, err)
		}
		if found.Results[0]["Source"] == nil || found.Results[0]["URL"] == nil {
			t.Fatal("missing citation", result)
		}
		result, err = executeChatTool(ctx, "read", map[string]interface{}{"path": tc.path})
		if err != nil || !strings.Contains(result, `"source":`) {
			t.Fatalf("%s read: %s %v", tc.kind, result, err)
		}
	}
	full := "patience " + strings.Repeat("complete passage ", 100)
	if _, err := db.DB.Exec(`INSERT INTO quran(chapter,chapter_name,verse,text) VALUES(2,'Al-Baqarah',153,?)`, full); err != nil {
		t.Fatal(err)
	}
	result, err := executeChatTool(ctx, "read", map[string]interface{}{"path": "/quran/2/153"})
	if err != nil || !strings.Contains(result, full) {
		t.Fatal("full text truncated", err)
	}
	result, err = executeChatTool(ctx, "search", map[string]interface{}{"q": "private sentinel"})
	if err != nil || strings.Contains(result, "private sentinel") {
		t.Fatal("private content in reference search", result, err)
	}
	for _, path := range []string{"/notes/1", "/chat/1", "https://example.com"} {
		if _, err := executeChatTool(ctx, "read", map[string]interface{}{"path": path}); err == nil {
			t.Fatal("invalid reference accepted", path)
		}
	}
	if _, err := executeChatTool(ctx, "search", map[string]interface{}{"q": "mercy", "limit": 51}); err == nil {
		t.Fatal("invalid limit accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := executeChatTool(canceled, "collections", nil); err != context.Canceled {
		t.Fatal("cancellation ignored", err)
	}
}
