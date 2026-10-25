package server

import "testing"

func TestSignupRequiresSenderAndHonorsDisable(t *testing.T) {
	for _, key := range []string{"SMTP_HOST", "SMTP_PORT", "SMTP_FROM", "SMTP_USERNAME", "SMTP_PASSWORD", "GMAIL_USER", "GMAIL_APP_PASSWORD"} {
		t.Setenv(key, "")
	}
	t.Setenv("ALLOW_PASSWORD_SIGNUP", "true")
	if passwordSignupEnabled() {
		t.Fatal("signup enabled without sender")
	}
	t.Setenv("SMTP_HOST", "smtp-relay.gmail.com")
	t.Setenv("SMTP_FROM", "noreply@aslam.org")
	if !passwordSignupEnabled() {
		t.Fatal("configured relay rejected")
	}
	t.Setenv("ALLOW_PASSWORD_SIGNUP", "false")
	if passwordSignupEnabled() {
		t.Fatal("disable ignored")
	}
}
