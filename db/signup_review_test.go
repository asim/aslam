package db

import (
	"context"
	"testing"
	"time"
)

func TestSignupRequiresVerificationAndApproval(t *testing.T) {
	setupTestDB(t)
	const email = "reader@example.com"
	if err := SavePendingSignup(email, "Reader", "hash", "token", time.Minute, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := ReviewSignup(context.Background(), email, "token", true); err == nil {
		t.Fatal("unverified approval succeeded")
	}
	if _, err := VerifyUserByToken("token"); err != nil {
		t.Fatal(err)
	}
	if UserExists(email) || IsUser(email) {
		t.Fatal("verification activated account")
	}
	if _, err := VerifyUserByToken("token"); err == nil {
		t.Fatal("token replay accepted")
	}
	if err := SavePendingSignup(email, "Attacker", "replacement", "new-token", 0, 24*time.Hour); err == nil {
		t.Fatal("verified request overwritten")
	}
	requests, err := GetSignupRequests(context.Background())
	if err != nil || len(requests) != 1 || !requests[0].Verified {
		t.Fatal(requests, err)
	}
	if err := ReviewSignup(context.Background(), email, "wrong-token", true); err == nil {
		t.Fatal("stale approval succeeded")
	}
	if err := ReviewSignup(context.Background(), email, "token", true); err != nil {
		t.Fatal(err)
	}
	if !IsUser(email) {
		t.Fatal("approved account unavailable")
	}
	u, err := GetUserByEmail(email)
	if err != nil || u.Name != "Reader" || u.PasswordHash != "hash" {
		t.Fatal(u, err)
	}
	if err := ReviewSignup(context.Background(), email, "token", true); err == nil {
		t.Fatal("approval replay accepted")
	}
}
func TestSignupRejectAndExpiry(t *testing.T) {
	setupTestDB(t)
	SavePendingSignup("expired@example.com", "Reader", "hash", "expired", 0, -time.Hour)
	if _, err := VerifyUserByToken("expired"); err == nil {
		t.Fatal("expired verification accepted")
	}
	SavePendingSignup("reject@example.com", "Reader", "hash", "reject", 0, time.Hour)
	VerifyUserByToken("reject")
	if err := ReviewSignup(context.Background(), "reject@example.com", "reject", false); err != nil {
		t.Fatal(err)
	}
	if UserExists("reject@example.com") {
		t.Fatal("rejection created account")
	}
	if _, err := VerifyUserByToken("reject"); err == nil {
		t.Fatal("rejected token reused")
	}
	SavePendingSignup("late@example.com", "Reader", "hash", "late", 0, time.Hour)
	VerifyUserByToken("late")
	DB.Exec(`UPDATE pending_signups SET expires_at=datetime('now','-1 day') WHERE email='late@example.com'`)
	if err := ReviewSignup(context.Background(), "late@example.com", "late", true); err == nil {
		t.Fatal("expired approval accepted")
	}
}
