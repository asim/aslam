package db

import (
	"os"
	"path/filepath"
	"testing"
)

// setupTestDB initialises a fresh encrypted SQLite db in a temp dir.
func setupTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	os.Setenv("ASLAM_KEY", "test-key-for-tests-only")
	os.Setenv("ASLAM_DB", filepath.Join(dir, "test.db"))
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	t.Cleanup(func() {
		Close()
	})
}

func TestIslamQASlugRoundTrip(t *testing.T) {
	setupTestDB(t)
	ClearIslamQA()
	if err := InsertIslamQA("Aqidah", "Can Babies See the Angels?", "Praise be to Allah..."); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	slug := Slug("Can Babies See the Angels?", "Can Babies See the Angels?|Praise be to Allah...")
	item, err := GetIslamQA(slug)
	if err != nil {
		t.Fatalf("GetIslamQA(%q) failed: %v", slug, err)
	}
	if item["Question"] != "Can Babies See the Angels?" {
		t.Errorf("question mismatch: got %v", item["Question"])
	}
}

func TestIslamQASlugSurvivesReload(t *testing.T) {
	setupTestDB(t)
	ClearIslamQA()
	InsertIslamQA("A", "Q1", "A1")
	InsertIslamQA("A", "Q2", "A2")

	slug1 := Slug("Q1", "Q1|A1")
	first, err := GetIslamQA(slug1)
	if err != nil {
		t.Fatalf("first lookup failed: %v", err)
	}

	ClearIslamQA()
	// Reload in opposite order — the autoincrement ids will differ.
	InsertIslamQA("A", "Q2", "A2")
	InsertIslamQA("A", "Q1", "A1")
	second, err := GetIslamQA(slug1)
	if err != nil {
		t.Fatalf("post-reload lookup failed: %v", err)
	}
	if first["Question"] != second["Question"] {
		t.Errorf("slug should return the same question after reload: %v vs %v", first["Question"], second["Question"])
	}
}

func TestAdhkarSlugRoundTrip(t *testing.T) {
	setupTestDB(t)
	ClearAdhkar()
	if err := InsertAdhkar("daily", "Supplication Before Sleeping", "arabic", "translit", "trans", "", "", "Bukhari"); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	canonical := "daily|Supplication Before Sleeping|arabic|trans"
	slug := Slug("Supplication Before Sleeping", canonical)
	item, err := GetAdhkar(slug)
	if err != nil {
		t.Fatalf("GetAdhkar(%q) failed: %v", slug, err)
	}
	if item["Title"] != "Supplication Before Sleeping" {
		t.Errorf("title mismatch: got %v", item["Title"])
	}
}

func TestGhazaliSlugRoundTrip(t *testing.T) {
	setupTestDB(t)
	if err := InsertGhazali(1, "The Book of Worship", "Chapter I: Knowledge", 1, "On the merits of knowledge..."); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	title := "v1 Chapter I: Knowledge p1"
	canonical := "1|Chapter I: Knowledge|1|On the merits of knowledge..."
	slug := Slug(title, canonical)
	item, err := GetGhazali(slug)
	if err != nil {
		t.Fatalf("GetGhazali(%q) failed: %v", slug, err)
	}
	if item["Chapter"] != "Chapter I: Knowledge" {
		t.Errorf("chapter mismatch: got %v", item["Chapter"])
	}
}

func TestHadithLookupByNumber(t *testing.T) {
	setupTestDB(t)
	ClearHadith()
	if err := InsertHadith("Revelation", 1, 42, "Narrated 'Umar:", "The reward of deeds...", "إنما الأعمال"); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	item, err := GetHadith(42)
	if err != nil {
		t.Fatalf("GetHadith(42) failed: %v", err)
	}
	if item["Number"] != 42 {
		t.Errorf("number mismatch: got %v", item["Number"])
	}
	if item["BookNumber"].(int64) != 1 {
		t.Errorf("book_number mismatch: got %v", item["BookNumber"])
	}
}

func TestRiyadLookupByNumber(t *testing.T) {
	setupTestDB(t)
	ClearRiyad()
	if err := InsertRiyad("The Book of Miscellany", 1, "Narrated 'Umar:", "The deeds are considered...", "إنما الأعمال"); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	item, err := GetRiyad(1)
	if err != nil {
		t.Fatalf("GetRiyad(1) failed: %v", err)
	}
	if item["Number"] != 1 {
		t.Errorf("number mismatch: got %v", item["Number"])
	}
	if item["Book"] != "The Book of Miscellany" {
		t.Errorf("book mismatch: got %v", item["Book"])
	}
}

func TestNameLookupByNumber(t *testing.T) {
	setupTestDB(t)
	ClearNames()
	if err := InsertName(2, "Ar-Raheem", "الرحيم", "The Merciful", "desc", "summary"); err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	item, err := GetName(2)
	if err != nil {
		t.Fatalf("GetName(2) failed: %v", err)
	}
	if item["English"] != "Ar-Raheem" {
		t.Errorf("english mismatch: got %v", item["English"])
	}
}
