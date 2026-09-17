package db

import (
	"aslam/internal/seerah"
	"database/sql"
	"strings"
	"testing"
)

func TestSeerahIndexAndReadingProgress(t *testing.T) {
	old := DB
	var err error
	DB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	DB.SetMaxOpenConns(1)
	defer func() { DB.Close(); DB = old }()
	b, err := seerah.Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := IndexSeerah(b); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := DB.QueryRow(`SELECT count(*) FROM seerah_fts`).Scan(&count); err != nil || count != 316 {
		t.Fatalf("index count %d: %v", count, err)
	}
	matches, matchErr := SearchSeerah("originated")
	if matchErr != nil {
		t.Fatal(matchErr)
	}
	found := false
	for _, match := range matches {
		if match["URL"] == "/seerah/page/8" {
			found = true
			if !strings.Contains(strings.ToLower(match["Content"].(string)), "originated") {
				t.Fatal("snippet omitted late-page match")
			}
		}
	}
	if !found {
		t.Fatal("missing page 8 result")
	}
	results, err := SearchSeerah("Hira")
	if err != nil || len(results) == 0 {
		t.Fatalf("search: %v %v", results, err)
	}
	if _, err := DB.Exec(`CREATE TABLE reading_progress(user_id INTEGER, source TEXT, path TEXT, title TEXT, updated_at TEXT, UNIQUE(user_id,source))`); err != nil {
		t.Fatal(err)
	}
	SaveReadingProgress(1, "seerah", "/seerah/page/44", "page 44")
	SaveReadingProgress(1, "seerah", "/seerah/page/45?section=block-2#block-2", "page 45")
	SaveReadingProgress(2, "seerah", "/seerah/page/8", "page 8")
	p, _ := GetReadingProgress(1, "seerah")
	if p != "/seerah/page/45?section=block-2#block-2" {
		t.Fatalf("resume path %s", p)
	}
	p, _ = GetReadingProgress(2, "seerah")
	if p != "/seerah/page/8" {
		t.Fatal("progress leaked between users")
	}
}
