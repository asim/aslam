package server

import (
	"aslam/db"
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChatComposerOnlyForOwner(t *testing.T) {
	tpl := template.New("").Funcs(template.FuncMap{"formatTime": func(time.Time) string { return "" }})
	tpl, err := tpl.Parse(`{{define "style"}}{{end}}{{define "header"}}{{end}}`)
	if err != nil {
		t.Fatal(err)
	}
	tpl, err = tpl.ParseFiles("html/chat.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, canSend := range []bool{false, true} {
		var out bytes.Buffer
		err := tpl.ExecuteTemplate(&out, "chat.html", map[string]interface{}{
			"Conversation": db.Conversation{ID: 1, Title: "Shared"},
			"CanSend":      canSend, "UserName": "Owner", "ViewerName": "Visitor",
			"Messages": []db.Message{{Role: "user", Content: "Question"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), `id="chat-form"`) != canSend {
			t.Fatal("incorrect composer visibility")
		}
		if !strings.Contains(out.String(), `class="message-role">Owner`) {
			t.Fatal("incorrect saved author")
		}
	}
}

func TestSharedChatRejectsMessages(t *testing.T) {
	t.Setenv("ASLAM_KEY", "chat-test-key")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		"INSERT INTO users(id,email,name,role) VALUES(1,'owner@test','Owner','user'),(2,'viewer@test','Viewer','user'),(3,'admin@test','Admin','admin')",
		"INSERT INTO conversations(id,title,user_id,public) VALUES(1,'Shared',1,1),(2,'Private',1,0),(3,'Orphan',NULL,1)",
	} {
		if _, err := db.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for _, email := range []string{"viewer@test", "admin@test", ""} {
		token := ""
		if email != "" {
			var err error
			token, err = db.CreateSession(email, email)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, id := range []int{1, 2, 3} {
			for _, api := range []bool{false, true} {
				body := fmt.Sprintf("conversation_id=%d&message=hello", id)
				if api {
					body = fmt.Sprintf("{\"conversation_id\":%d,\"message\":\"hello\"}", id)
				}
				r := httptest.NewRequest("POST", "/chat/send", strings.NewReader(body))
				if api {
					r.Header.Set("Content-Type", "application/json")
				} else {
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if token != "" {
					r.AddCookie(&http.Cookie{Name: "session", Value: token})
				}
				w := httptest.NewRecorder()
				if api {
					handleAPISendMessage(w, r)
				} else {
					handleSendMessage(w, r)
				}
				if w.Code != http.StatusForbidden {
					t.Fatalf("email=%s id=%d api=%v: %d %s", email, id, api, w.Code, w.Body.String())
				}
			}
		}
	}
	var count int
	if err := db.DB.QueryRow("SELECT count(*) FROM messages").Scan(&count); err != nil || count != 0 {
		t.Fatalf("messages=%d err=%v", count, err)
	}
	token, err := db.CreateSession("owner@test", "Owner")
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/chat/send", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: token})
	if !canSendChatMessage(httptest.NewRecorder(), r, 1) {
		t.Fatal("owner cannot send")
	}
}
