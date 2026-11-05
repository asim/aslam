package server

import (
	"aslam/db"
	"html/template"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestVerificationDoesNotIssueSession(t *testing.T) {
	t.Setenv("ASLAM_KEY", "test-key")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "approval.db"))
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	previous := tmpl
	defer func() { tmpl = previous }()
	tmpl = template.Must(template.New("").Parse(`{{define "verify_sent.html"}}{{if .AwaitingApproval}}Awaiting approval{{end}}{{end}}{{define "login.html"}}{{.Error}}{{end}}`))
	if err := db.SavePendingSignup("reader@example.com", "Reader", "hash", "token", 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleVerify(w, httptest.NewRequest("GET", "https://aslam.org/auth/verify?token=token", nil))
	if !strings.Contains(w.Body.String(), "Awaiting approval") || len(w.Result().Cookies()) != 0 || db.UserExists("reader@example.com") {
		t.Fatal("verification activated account", w.Body.String())
	}
}
