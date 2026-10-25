package db

import (
	"context"
	"fmt"
	"testing"
)

func TestBoundedIndexesAndDailyQuestion(t *testing.T) {
	limitedTestDB(t)
	for _, q := range []string{
		`CREATE TABLE islamqa(id INTEGER PRIMARY KEY,slug TEXT,category TEXT,question TEXT)`,
		`CREATE TABLE notes_v2(id INTEGER PRIMARY KEY,title TEXT,user_id INTEGER,updated_at DATETIME)`,
	} {
		if _, err := DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 120; i++ {
		cat := "A"
		if i > 100 {
			cat = "B"
		}
		if _, err := DB.Exec(`INSERT INTO islamqa VALUES(?,?,?,?)`, i, fmt.Sprint(i), cat, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	first, err := GetIslamQAPageContext(ctx, "", 0)
	if err != nil || len(first) != 51 {
		t.Fatal(len(first), err)
	}
	next, err := GetIslamQAPageContext(ctx, "", 50)
	if err != nil || next[0]["ID"] != first[50]["ID"] {
		t.Fatal(next, err)
	}
	category, err := GetIslamQAPageContext(ctx, "B", 0)
	if err != nil || len(category) != 20 {
		t.Fatal(len(category), err)
	}
	today, err := GetDailyIslamQAContext(ctx, "2026-10-25")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := GetDailyIslamQAContext(ctx, "2026-10-25")
	if today["ID"] != again["ID"] {
		t.Fatal("daily question changed")
	}
	tomorrow, _ := GetDailyIslamQAContext(ctx, "2026-10-26")
	if today["ID"] == tomorrow["ID"] {
		t.Fatal("fixture did not rotate")
	}
	for i := 1; i <= 5; i++ {
		if _, err := DB.Exec(`INSERT INTO notes_v2 VALUES(?,?,?,CURRENT_TIMESTAMP)`, i, fmt.Sprint(i), 1); err != nil {
			t.Fatal(err)
		}
	}
	DB.Exec(`INSERT INTO notes_v2 VALUES(6,'other user',2,CURRENT_TIMESTAMP)`)
	notes, err := GetRecentNotesContext(ctx, 1)
	if err != nil || len(notes) != 3 || notes[0].ID != 5 {
		t.Fatal(notes, err)
	}
	none, _ := GetRecentNotesContext(ctx, 0)
	if len(none) != 0 {
		t.Fatal("anonymous notes leaked")
	}
}
