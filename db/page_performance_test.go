package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkEncryptedConnectionReuse(b *testing.B) {
	b.Setenv("ASLAM_KEY", "benchmark-key")
	b.Setenv("ASLAM_DB", filepath.Join(b.TempDir(), "bench.db"))
	old := DB
	if err := Init(); err != nil {
		b.Fatal(err)
	}
	defer func() { Close(); DB = old }()
	for _, tc := range []struct {
		name string
		idle int
	}{{"reopen", 0}, {"reuse", 4}} {
		b.Run(tc.name, func(b *testing.B) {
			DB.SetMaxIdleConns(tc.idle)
			var count int
			if err := DB.QueryRow("SELECT count(*) FROM users").Scan(&count); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := DB.QueryRowContext(context.Background(), "SELECT count(*) FROM users").Scan(&count); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestPageQueriesUseOrderedIndexes(t *testing.T) {
	limitedTestDB(t)
	if err := Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, query, index string }{
		{"quran", "SELECT verse,text FROM quran WHERE chapter=2 ORDER BY verse", "idx_quran_chapter_verse"},
		{"hadith", "SELECT number,narrator FROM hadith WHERE book_number=2 ORDER BY number", "idx_hadith_book_number"},
		{"islamqa", "SELECT id,question FROM islamqa ORDER BY category,id LIMIT 51", "idx_islamqa_category_id"},
		{"arabic", "SELECT id,arabic,english FROM arabic ORDER BY frequency DESC LIMIT 50", "idx_arabic_frequency"},
		{"notes", "SELECT id,title FROM notes_v2 WHERE user_id=1 ORDER BY updated_at DESC,id DESC LIMIT 3", "idx_notes_v2_user_updated"},
		{"chats", "SELECT id,title FROM conversations WHERE user_id=1 ORDER BY updated_at DESC LIMIT 3", "idx_conversations_user_updated"},
		{"reminder", "SELECT verse FROM reminder_content ORDER BY fetched_at DESC LIMIT 1", "idx_reminder_content_fetched"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := DB.Query("EXPLAIN QUERY PLAN " + tc.query)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var plan string
			for rows.Next() {
				var a, b, c int
				var detail string
				if err := rows.Scan(&a, &b, &c, &detail); err != nil {
					t.Fatal(err)
				}
				plan += detail + "\n"
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan, tc.index) || strings.Contains(plan, "TEMP B-TREE") {
				t.Fatalf("unindexed/sorted page query: %s", plan)
			}
		})
	}
}

func BenchmarkVocabularyPage(b *testing.B) {
	b.Setenv("ASLAM_KEY", "benchmark-key")
	b.Setenv("ASLAM_DB", filepath.Join(b.TempDir(), "bench.db"))
	old := DB
	if err := Init(); err != nil {
		b.Fatal(err)
	}
	defer func() { Close(); DB = old }()
	tx, err := DB.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare("INSERT INTO arabic(arabic,english,frequency) VALUES(?,?,?)")
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 21000; i++ {
		if _, err := stmt.Exec("كتاب", strings.Repeat("sample ", 20), (i*7919)%21000); err != nil {
			b.Fatal(err)
		}
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	for _, indexed := range []bool{false, true} {
		name := "without_index"
		if indexed {
			name = "with_index"
			if err := initPageIndexes(); err != nil {
				b.Fatal(err)
			}
		} else {
			if _, err := DB.Exec("DROP INDEX idx_arabic_frequency"); err != nil {
				b.Fatal(err)
			}
		}
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := GetArabicByFrequencyRangeContext(context.Background(), 0, 50); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
