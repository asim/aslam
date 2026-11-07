package server

import (
	"aslam/db"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func modelTestContext(t *testing.T) context.Context {
	t.Helper()
	t.Setenv("ASLAM_KEY", "model-test")
	t.Setenv("ASLAM_DB", filepath.Join(t.TempDir(), "test.db"))
	t.Setenv("MODEL_ENABLED", "true")
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.DB.Exec("INSERT INTO users(id,email,verified) VALUES(1,'test@example.com',1); INSERT INTO conversations(id,title,user_id) VALUES(1,'test',1)"); err != nil {
		t.Fatal(err)
	}
	return context.WithValue(context.Background(), modelConversationKey{}, &modelQuery{conversationID: 1})
}
func TestModelGuardStopsOutboundRequests(t *testing.T) {
	ctx := modelTestContext(t)
	db.SetSetting("model_user_daily_question_limit", "1")
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	calls := 0
	http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, errors.New("provider failed") })
	callAnthropic(ctx, nil, "test")
	if calls != 1 {
		t.Fatalf("first call missing: %d", calls)
	}
	next := context.WithValue(ctx, modelConversationKey{}, &modelQuery{conversationID: 1})
	_, _, err := callAnthropicStream(next, nil, "test", func(string) {})
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

func TestFollowupsShareQuestionAllowance(t *testing.T) {
	ctx := modelTestContext(t)
	if err := db.SetSetting("model_user_daily_question_limit", "1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		release, err := reserveModelRequest(ctx, 10)
		if err != nil {
			t.Fatalf("followup %d: %v", i, err)
		}
		release()
	}
	next := context.WithValue(ctx, modelConversationKey{}, &modelQuery{conversationID: 1})
	if _, err := reserveModelRequest(next, 10); !errors.Is(err, db.ErrModelBudget) {
		t.Fatalf("second question: %v", err)
	}
	usage, err := db.GetModelUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range usage {
		if v.Calls != 1 {
			t.Fatalf("followups counted: %+v", v)
		}
	}
	activity, err := db.GetModelActivity(ctx)
	if err != nil || len(activity) != 1 || activity[0].Questions != 1 || activity[0].LastActive == "" {
		t.Fatalf("activity: %+v, %v", activity, err)
	}
}

func TestAdminModelLimits(t *testing.T) {
	ctx := modelTestContext(t)
	if modelDailyLimit("model_user_daily_question_limit", 5) != 5 || modelDailyLimit("model_daily_question_limit", 0) != 0 {
		t.Fatal("wrong defaults")
	}
	post := func(body, origin string) int {
		r := httptest.NewRequest("POST", "http://example.com/admin/model-limits", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handleModelLimits(w, r)
		return w.Code
	}
	if post("user_limit=2&global_limit=10", "http://evil.com") != 403 {
		t.Fatal("cross-origin accepted")
	}
	if post("user_limit=-1&global_limit=10", "http://example.com") != 400 {
		t.Fatal("invalid accepted")
	}
	if post("user_limit=2&global_limit=10", "http://example.com") != 303 {
		t.Fatal("save failed")
	}
	if modelDailyLimit("model_user_daily_question_limit", 5) != 2 || modelDailyLimit("model_daily_question_limit", 0) != 10 {
		t.Fatal("settings not applied")
	}
	if post("user_limit=0&global_limit=0", "http://example.com") != 303 {
		t.Fatal("disable failed")
	}
	if _, err := reserveModelRequest(ctx, 10); !errors.Is(err, db.ErrModelBudget) {
		t.Fatalf("zero user limit: %v", err)
	}
}
