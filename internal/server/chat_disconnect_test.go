package server

import (
	"aslam/db"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestChatAnswerSavedAfterDisconnect(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "form"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			modelTestContext(t)
			token, err := db.CreateSession("test@example.com", "Reader")
			if err != nil {
				t.Fatal(err)
			}
			original, disconnect := context.WithCancel(context.Background())
			defer disconnect()
			oldTransport, oldKey, oldUser := http.DefaultTransport, anthropicKey, currentUserContext
			t.Cleanup(func() { http.DefaultTransport = oldTransport; anthropicKey = oldKey; currentUserContext = oldUser })
			anthropicKey = "test-key"
			calls := 0
			http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				disconnect()
				if err := r.Context().Err(); err != nil {
					t.Fatalf("generation canceled by disconnect: %v", err)
				}
				if _, ok := r.Context().Deadline(); !ok {
					t.Fatal("generation has no deadline")
				}
				body := `{"content":[{"type":"text","text":"The saved answer."}],"stop_reason":"end_turn"}`
				if stream {
					body = "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"The saved answer.\"}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n"
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			path, body, contentType := "/chat/send", "conversation_id=1&message=Question", "application/x-www-form-urlencoded"
			if stream {
				path, body, contentType = "/api/chat/send", `{"conversation_id":1,"message":"Question"}`, "application/json"
			}
			r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(original)
			r.Header.Set("Content-Type", contentType)
			r.AddCookie(&http.Cookie{Name: "session", Value: token})
			w := httptest.NewRecorder()
			if stream {
				handleAPISendMessage(w, r)
			} else {
				handleSendMessage(w, r)
			}
			messages, err := db.GetMessages(1)
			if err != nil || len(messages) != 2 || messages[1].Role != "assistant" || messages[1].Content != "The saved answer." || calls != 1 {
				t.Fatalf("messages=%+v calls=%d err=%v status=%d", messages, calls, err, w.Code)
			}
			// Recovery uses a fresh request, not the disconnected stream's context.
			recovery := httptest.NewRequest("GET", "/api/chat/latest?id=1", nil)
			recovery.AddCookie(&http.Cookie{Name: "session", Value: token})
			recovered := httptest.NewRecorder()
			handleAPIChatLatest(recovered, recovery)
			if recovered.Code != http.StatusOK || !strings.Contains(recovered.Body.String(), "The saved answer.") {
				t.Fatalf("recovery failed: %d %s", recovered.Code, recovered.Body.String())
			}
			var questions int
			if err := db.DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=1").Scan(&questions); err != nil || questions != 1 {
				t.Fatalf("questions=%d err=%v", questions, err)
			}
		})
	}
}

func TestChatGenerationKeepsDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	parent, cancelParent := context.WithDeadline(context.Background(), deadline)
	ctx, cancel := chatGenerationContext(parent)
	defer cancel()
	cancelParent()
	if ctx.Err() != nil {
		t.Fatal("disconnect canceled generation")
	}
	if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
		t.Fatal("original deadline was extended")
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("generation cleanup did not cancel")
	}
	expired, cleanup := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cleanup()
	ctx, cancel = chatGenerationContext(expired)
	defer cancel()
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatal("expired server deadline ignored")
	}
}
