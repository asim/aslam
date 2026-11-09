package server

import (
	"aslam/db"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Exercise both complete response paths, including the real question guard.
// An unknown tool yields a local error result without external I/O; the model
// must be able to recover from these results beyond the old five-call cutoff.
func TestToolFollowupsDoNotConsumeQuestions(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, cancelAfterTools := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%v/cancel=%v", stream, cancelAfterTools), func(t *testing.T) {
				base := modelTestContext(t)
				if err := db.SetSetting("model_user_daily_question_limit", "1"); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(base)
				defer cancel()
				oldTransport, oldKey := http.DefaultTransport, anthropicKey
				t.Cleanup(func() { http.DefaultTransport = oldTransport; anthropicKey = oldKey })
				anthropicKey = "test-key"
				calls := 0
				http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					if calls > 7 {
						t.Fatal("unexpected provider call")
					}
					var request struct {
						Messages []json.RawMessage `json:"messages"`
					}
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Fatal(err)
					}
					if len(request.Messages) != 1+2*(calls-1) {
						t.Fatalf("lost tool history: %d messages", len(request.Messages))
					}
					reason := "end_turn"
					block := contentBlock{Type: "text", Text: "Answer from the available sources."}
					if calls <= 6 {
						reason = "tool_use"
						block = contentBlock{Type: "tool_use", ID: fmt.Sprintf("tool-%d", calls), Name: "test_lookup", Input: map[string]interface{}{"query": "patience"}}
					}
					var body string
					if stream {
						event := func(v interface{}) {
							data, err := json.Marshal(v)
							if err != nil {
								t.Fatal(err)
							}
							body += "data: " + string(data) + "\n\n"
						}
						event(map[string]interface{}{"type": "content_block_start", "content_block": block})
						if reason == "tool_use" {
							event(map[string]interface{}{"type": "content_block_delta", "delta": map[string]string{"type": "input_json_delta", "partial_json": "{\"query\":\"patience\"}"}})
						} else {
							event(map[string]interface{}{"type": "content_block_delta", "delta": map[string]string{"type": "text_delta", "text": block.Text}})
						}
						event(map[string]string{"type": "content_block_stop"})
						event(map[string]interface{}{"type": "message_delta", "delta": map[string]string{"stop_reason": reason}})
					} else {
						data, err := json.Marshal(anthropicResponse{Content: []contentBlock{block}, StopReason: reason})
						if err != nil {
							t.Fatal(err)
						}
						body = string(data)
					}
					if cancelAfterTools && calls == 6 {
						cancel()
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})
				messages := []db.Message{{Role: "user", Content: "What do the sources say about patience?"}}
				var answer string
				var used []ToolUsage
				var err error
				var delivered strings.Builder
				if stream {
					answer, used, err = generateResponseStreaming(ctx, messages, 1, func(s string) { delivered.WriteString(s) })
				} else {
					answer, used, err = generateResponseWithProgressContext(ctx, messages, 1, nil)
				}
				if cancelAfterTools {
					if !errors.Is(err, context.Canceled) || calls != 6 {
						t.Fatalf("cancellation: calls=%d err=%v", calls, err)
					}
				} else {
					if err != nil || calls != 7 || len(used) != 6 || answer != "Answer from the available sources." {
						t.Fatalf("answer=%q tools=%d calls=%d err=%v", answer, len(used), calls, err)
					}
					if stream && !strings.Contains(delivered.String(), answer) {
						t.Fatal("answer not delivered")
					}
				}
				var questions int
				if err := db.DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=1").Scan(&questions); err != nil || questions != 1 {
					t.Fatalf("questions=%d err=%v", questions, err)
				}
				next := context.WithValue(base, modelConversationKey{}, &modelQuery{conversationID: 1})
				if _, err := reserveModelRequest(next, 10); !errors.Is(err, db.ErrModelBudget) {
					t.Fatalf("next question was not limited: %v", err)
				}
			})
		}
	}
}
