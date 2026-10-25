package server

import (
	"archive/zip"
	"aslam/data"
	"aslam/db"
	"aslam/internal/arabiclearning"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

// Exercise the real FTS search against actual bundled forms, not invented
// headwords: kitāb and maktūb are stored with grammatical endings.
func TestRootVocabularyLinksFindBundledWords(t *testing.T) {
	b, err := arabiclearning.Load()
	if err != nil {
		t.Fatal(err)
	}
	queries := map[string]bool{}
	for _, root := range b.Roots {
		for _, w := range root.Words {
			if w.VocabularyQuery != "" {
				queries[w.VocabularyQuery] = false
			}
		}
	}
	if len(queries) == 0 {
		t.Fatal("no vocabulary links")
	}
	z, err := zip.NewReader(bytes.NewReader(data.Arabic), int64(len(data.Arabic)))
	if err != nil {
		t.Fatal(err)
	}
	f, err := z.Open("arabic_vocab.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var entries []struct {
		Arabic, Transliteration, English string
		Frequency                        int
	}
	if err = json.NewDecoder(f).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASLAM_KEY", "root-links-test")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err = db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, entry := range entries {
		if _, ok := queries[entry.Transliteration]; !ok {
			continue
		}
		if err = db.InsertArabicWord(entry.Arabic, entry.Transliteration, entry.English, entry.Frequency, "", ""); err != nil {
			t.Fatal(err)
		}
		queries[entry.Transliteration] = true
	}
	for query, found := range queries {
		if !found {
			t.Fatalf("link %q has no bundled form", query)
		}
		results, err := db.SearchArabicContext(context.Background(), query)
		if err != nil || len(results) == 0 {
			t.Fatalf("link %q: results=%v err=%v", query, results, err)
		}
	}
}
