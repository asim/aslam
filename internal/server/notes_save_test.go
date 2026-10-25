package server

import (
	"aslam/db"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoteSaveResponses(t *testing.T) {
	t.Setenv("ASLAM_KEY", "note-test")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	send := func(title string, quick bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/notes/add", strings.NewReader(url.Values{"title": {title}, "content": {"https://www.youtube.com/watch?v=testvideo"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Referer", "/notes")
		if quick {
			r.Header.Set("Accept", "application/json")
		}
		w := httptest.NewRecorder()
		handleNoteAdd(w, r)
		return w
	}
	w := send("Video", false)
	if w.Code != 303 || w.Header().Get("Location") != "/notes" {
		t.Fatal(w.Code, w.Header())
	}
	var content string
	if err := db.DB.QueryRow("SELECT content FROM notes_v2 WHERE title='Video'").Scan(&content); err != nil || !strings.Contains(content, "youtube.com") {
		t.Fatal(content, err)
	}
	w = send("Quick save", true)
	var result struct {
		Saved bool
		ID    int64
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 201 || !result.Saved || result.ID == 0 {
		t.Fatal(w.Code, w.Body.String(), err)
	}
	w = send("", true)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	if _, err := db.DB.Exec("DROP TABLE notes_v2"); err != nil {
		t.Fatal(err)
	}
	w = send("Failure", true)
	if w.Code != 500 || strings.Contains(w.Body.String(), `"saved":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
