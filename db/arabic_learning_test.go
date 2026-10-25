package db

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestArabicImportRollback(t *testing.T) {
	old := DB
	t.Setenv("ASLAM_KEY", "arabic-import-test")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	defer func() { DB.Close(); DB = old }()
	vocab := []ArabicVocabulary{{Arabic: "كِتَابٌ", Transliteration: "kitābun", English: "book", Roots: []ArabicRoot{{Code: "ktb", Arabic: "كتب", Lemma: "كِتَاب", Type: "N"}}}}
	passage := ArabicPassage{Chapter: 2, Verse: 2, Title: "2:2", Arabic: "test", English: "test", Words: []ArabicPassageWord{{Arabic: "كِتَابٌ", Transliteration: "kitābun"}}}
	if err := ImportArabic(vocab, []ArabicPassage{passage}, "test1"); err != nil {
		t.Fatal(err)
	}
	// Duplicate passage violates the primary key after roots have been replaced.
	if err := ImportArabic(nil, []ArabicPassage{passage, passage}, "test2"); err == nil {
		t.Fatal("expected rollback")
	}
	if GetSetting("arabic_version") != "test1" {
		t.Fatal("version committed on failure")
	}
	roots, err := ArabicRootsContext(context.Background(), "ktb", 0)
	if err != nil || len(roots) != 1 {
		t.Fatal("roots lost on rollback", err)
	}
	p, err := ArabicPassageContext(context.Background(), 2, 2)
	if err != nil || p.Words[0].VocabularyID == 0 {
		t.Fatal("passage lost on rollback", err)
	}
}
func TestArabicLearningQueriesCancel(t *testing.T) {
	limitedTestDB(t)
	conn, err := DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, lookup := range []func(context.Context) error{
		func(ctx context.Context) error { _, e := ArabicRootsContext(ctx, "", 0); return e },
		func(ctx context.Context) error { _, e := ArabicRootWordsContext(ctx, "ktb", 0); return e },
		func(ctx context.Context) error { _, e := ArabicWordRootsContext(ctx, 1); return e },
		func(ctx context.Context) error { _, e := ArabicPassagesContext(ctx, 1, 5, 0); return e },
		func(ctx context.Context) error { _, e := ArabicPassageContext(ctx, 1, 1); return e },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		err := lookup(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}
}
