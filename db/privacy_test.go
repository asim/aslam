package db

import (
	"os"
	"path/filepath"
	"testing"
)

func setupPrivacyDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	os.Setenv("ASLAM_KEY", "test-key-for-tests-only")
	os.Setenv("ASLAM_DB", filepath.Join(dir, "test.db"))
	if err := Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	t.Cleanup(func() { Close() })
}

func TestOrphanConversationsHiddenFromNonAdmin(t *testing.T) {
	setupPrivacyDB(t)

	// One orphan + one owned by user 99
	DB.Exec(`INSERT INTO conversations (title, user_id) VALUES ('orphan', NULL)`)
	DB.Exec(`INSERT INTO conversations (title, user_id) VALUES ('mine', 99)`)

	// Non-admin, "all" view — should NOT see orphan
	convs, err := GetRecentConversations(50, 99, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range convs {
		if c.Title == "orphan" {
			t.Fatalf("non-admin saw orphan conversation in 'all' view")
		}
	}

	// Non-admin, "mine" view — should NOT see orphan
	convs, err = GetRecentConversations(50, 99, true, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range convs {
		if c.Title == "orphan" {
			t.Fatalf("non-admin saw orphan conversation in 'mine' view")
		}
	}

	// Admin sees orphan
	convs, err = GetRecentConversations(50, 99, false, true)
	if err != nil {
		t.Fatal(err)
	}
	sawOrphan := false
	for _, c := range convs {
		if c.Title == "orphan" {
			sawOrphan = true
		}
	}
	if !sawOrphan {
		t.Fatalf("admin did not see orphan conversation")
	}
}

func TestOrphanNotesHiddenFromNonAdmin(t *testing.T) {
	setupPrivacyDB(t)

	DB.Exec(`INSERT INTO notes_v2 (title, content, user_id) VALUES ('orphan note', 'x', NULL)`)
	DB.Exec(`INSERT INTO notes_v2 (title, content, user_id) VALUES ('mine note', 'x', 99)`)

	items, err := GetNoteItems(99, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range items {
		if n.Title == "orphan note" {
			t.Fatalf("non-admin saw orphan note")
		}
	}

	items, err = GetNoteItems(99, false, true)
	if err != nil {
		t.Fatal(err)
	}
	sawOrphan := false
	for _, n := range items {
		if n.Title == "orphan note" {
			sawOrphan = true
		}
	}
	if !sawOrphan {
		t.Fatalf("admin did not see orphan note")
	}
}

func TestAdoptOrphanConversation(t *testing.T) {
	setupPrivacyDB(t)

	res, _ := DB.Exec(`INSERT INTO conversations (title, user_id) VALUES ('orphan', NULL)`)
	id, _ := res.LastInsertId()

	AdoptOrphanConversation(id, 42)

	var uid int64
	DB.QueryRow(`SELECT user_id FROM conversations WHERE id = ?`, id).Scan(&uid)
	if uid != 42 {
		t.Fatalf("orphan not adopted: user_id = %d", uid)
	}

	// A second user calling adopt on an already-owned conversation must not steal it.
	AdoptOrphanConversation(id, 7)
	DB.QueryRow(`SELECT user_id FROM conversations WHERE id = ?`, id).Scan(&uid)
	if uid != 42 {
		t.Fatalf("adoption overwrote owner: user_id = %d (want 42)", uid)
	}
}

func TestAdoptOrphanNote(t *testing.T) {
	setupPrivacyDB(t)

	res, _ := DB.Exec(`INSERT INTO notes_v2 (title, content, user_id) VALUES ('orphan', 'x', NULL)`)
	id, _ := res.LastInsertId()

	AdoptOrphanNote(id, 42)

	var uid int64
	DB.QueryRow(`SELECT user_id FROM notes_v2 WHERE id = ?`, id).Scan(&uid)
	if uid != 42 {
		t.Fatalf("orphan note not adopted: user_id = %d", uid)
	}

	AdoptOrphanNote(id, 7)
	DB.QueryRow(`SELECT user_id FROM notes_v2 WHERE id = ?`, id).Scan(&uid)
	if uid != 42 {
		t.Fatalf("adoption overwrote owner: user_id = %d (want 42)", uid)
	}
}

func TestAdoptIgnoresZeroUser(t *testing.T) {
	setupPrivacyDB(t)

	res, _ := DB.Exec(`INSERT INTO conversations (title, user_id) VALUES ('orphan', NULL)`)
	id, _ := res.LastInsertId()

	// Unauthenticated caller (userID=0) must not adopt
	AdoptOrphanConversation(id, 0)

	var uid sqlNullable
	DB.QueryRow(`SELECT user_id FROM conversations WHERE id = ?`, id).Scan(&uid)
	if uid.Valid {
		t.Fatalf("orphan got adopted by zero user: user_id = %v", uid.Int)
	}
}

type sqlNullable struct {
	Int   int64
	Valid bool
}

func (n *sqlNullable) Scan(v interface{}) error {
	if v == nil {
		n.Valid = false
		return nil
	}
	n.Valid = true
	switch t := v.(type) {
	case int64:
		n.Int = t
	}
	return nil
}
