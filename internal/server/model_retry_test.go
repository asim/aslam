package server

import (
	"aslam/db"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTruncatedToolRetriesOriginalQuestion(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, exhaust := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%v/exhaust=%v", stream, exhaust), func(t *testing.T) {
				ctx := modelTestContext(t)
				db.SetSetting("model_user_daily_question_limit", "1")
				old := http.DefaultTransport
				oldKey := anthropicKey
				anthropicKey = "test"
				t.Cleanup(func() { anthropicKey = oldKey })
				t.Cleanup(func() { http.DefaultTransport = old })
				calls := 0
				var original string
				http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					var req struct {
						Messages  json.RawMessage `json:"messages"`
						MaxTokens int             `json:"max_tokens"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatal(err)
					}
					if calls == 1 {
						original = string(req.Messages)
					}
					if exhaust || calls <= 2 {
						if string(req.Messages) != original {
							t.Fatal("partial tool entered history")
						}
						if req.MaxTokens != 2048<<(calls-1) {
							t.Fatalf("budget %d", req.MaxTokens)
						}
					} else if !strings.Contains(string(req.Messages), "tool_result") || strings.Contains(string(req.Messages), "partial-id") {
						t.Fatal("invalid tool history", string(req.Messages))
					}
					if calls > 4 {
						t.Fatal("unbounded retry")
					}
					reason := "tool_use"
					block := contentBlock{Type: "tool_use", ID: "complete-id", Name: "test_lookup", Input: map[string]interface{}{"query": "patience"}}
					if exhaust || calls == 1 {
						reason = "max_tokens"
						block.ID = "partial-id"
						block.Input = nil
					} else if calls == 3 {
						reason = "end_turn"
						block = contentBlock{Type: "text", Text: "Answered."}
					}
					raw, _ := json.Marshal(anthropicResponse{Content: []contentBlock{block}, StopReason: reason})
					body := string(raw)
					if stream {
						start, _ := json.Marshal(block)
						body = "data: {\"type\":\"content_block_start\",\"content_block\":" + string(start) + "}\n\n"
						if block.Type == "tool_use" {
							input := `{"query":"patience"}`
							if reason == "max_tokens" {
								input = `{"query":"`
							}
							delta, _ := json.Marshal(map[string]interface{}{"type": "content_block_delta", "delta": map[string]string{"type": "input_json_delta", "partial_json": input}})
							body += "data: " + string(delta) + "\n\n"
						}
						// Exercise truncated streams without a content_block_stop, too.
						if reason != "max_tokens" {
							body += "data: {\"type\":\"content_block_stop\"}\n\n"
						}
						body += fmt.Sprintf("data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":%q}}\n\n", reason)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
				})
				messages := []db.Message{{Role: "user", Content: "Explain"}}
				var answer string
				var used []ToolUsage
				var err error
				if stream {
					answer, used, err = generateResponseStreaming(ctx, messages, 1, nil)
				} else {
					answer, used, err = generateResponseWithProgressContext(ctx, messages, 1, nil)
				}
				if exhaust {
					if err == nil || calls != 4 || len(used) != 0 {
						t.Fatal(answer, used, calls, err)
					}
				} else if err != nil || answer != "Answered." || calls != 3 || len(used) != 1 || !strings.Contains(used[0].Input, "patience") {
					t.Fatal(answer, used, calls, err)
				}
				var questions int
				db.DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=1").Scan(&questions)
				if questions != 1 {
					t.Fatal("retry charged another question", questions)
				}
			})
		}
	}
}
