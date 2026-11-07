package server

import (
	"aslam/db"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
)

func modelTestContext(t *testing.T) context.Context {
	t.Helper()
	t.Setenv("ASLAM_KEY", "model-test")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	t.Setenv("MODEL_ENABLED", "true")
	t.Setenv("MODEL_DAILY_CALL_LIMIT", "100")
	t.Setenv("MODEL_USER_DAILY_CALL_LIMIT", "20")
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.DB.Exec("INSERT INTO users(id,email,verified) VALUES(1,'test@example.com',1); INSERT INTO conversations(id,title,user_id) VALUES(1,'test',1)"); err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), modelConversationKey{}, int64(1))
}
func TestModelGuardStopsOutboundRequests(t *testing.T) {
	ctx := modelTestContext(t)
	t.Setenv("MODEL_USER_DAILY_CALL_LIMIT", "1")
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	calls := 0
	http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("provider failed") })
	callAnthropic(ctx, nil, "test")
	if calls != 1 {
		t.Fatalf("first call missing: %d", calls)
	}
	_, _, err := callAnthropicStream(ctx, nil, "test", func(string) {})
	if !errors.Is(err, db.ErrModelBudget) || calls != 1 {
		t.Fatalf("quota bypass: %v calls=%d", err, calls)
	}
	if _, err = callAnthropic(context.Background(), nil, "test"); err == nil || calls != 1 {
		t.Fatal("missing owner bypass")
	}
	t.Setenv("MODEL_ENABLED", "false")
	if _, err = callAnthropic(ctx, nil, "test"); err == nil || calls != 1 {
		t.Fatal("disabled bypass")
	}
}
func TestModelPayloadAndConcurrency(t *testing.T) {
	ctx := modelTestContext(t)
	if _, err := reserveModelRequest(ctx, (64<<10)+1); err == nil {
		t.Fatal("oversized request allowed")
	}
	a, err := reserveModelRequest(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	b, err := reserveModelRequest(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer b()
	if _, err := reserveModelRequest(ctx, 10); err == nil {
		t.Fatal("concurrency exceeded")
	}
}
