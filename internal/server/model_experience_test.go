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

func TestTruncatedAnswerContinuesWithinQuestion(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			ctx := modelTestContext(t)
			db.SetSetting("model_user_daily_question_limit", "1")
			old, key := http.DefaultTransport, anthropicKey
			t.Cleanup(func() { http.DefaultTransport = old; anthropicKey = key })
			anthropicKey = "test"
			calls := 0
			http.DefaultTransport = cancelTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 2 {
					t.Fatal("continuation loop")
				}
				var request map[string]interface{}
				json.NewDecoder(r.Body).Decode(&request)
				if calls == 2 {
					raw, _ := json.Marshal(request["messages"])
					if !strings.Contains(string(raw), continueAnswer) {
						t.Fatal("missing continuation instruction")
					}
				}
				text, reason := "First part. ", "max_tokens"
				if calls == 2 {
					text, reason = "Finished.", "end_turn"
				}
				body, _ := json.Marshal(anthropicResponse{Content: []contentBlock{{Type: "text", Text: text}}, StopReason: reason})
				if stream {
					body = []byte(fmt.Sprintf("data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":%q}}\n\ndata: {\"type\":\"content_block_stop\"}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":%q}}\n\n", text, reason))
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})
			messages := []db.Message{{Role: "user", Content: "Explain"}}
			var answer, delivered string
			var err error
			if stream {
				answer, _, err = generateResponseStreaming(ctx, messages, 1, func(text string) { delivered += text })
			} else {
				answer, _, err = generateResponseWithProgressContext(ctx, messages, 1, nil)
			}
			if err != nil || answer != "First part. Finished." || calls != 2 {
				t.Fatal(answer, calls, err)
			}
			if stream && answer != delivered {
				t.Fatal("stream/save differ", delivered, answer)
			}
			var questions int
			db.DB.QueryRow("SELECT calls FROM model_daily_usage WHERE user_id=1").Scan(&questions)
			if questions != 1 {
				t.Fatal("continuation charged another question")
			}
		})
	}
}
func TestEvidenceSurvivesFollowup(t *testing.T) {
	ctx := modelTestContext(t)
	evidence := `{"source":"Quran","url":"https://aslam.org/quran/2/153","resource":{"Text":"patient evidence"}}`
	if err := db.SaveToolEvidence(ctx, 1, "read", `{"path":"/quran/2/153"}`, evidence); err != nil {
		t.Fatal(err)
	}
	messages, err := addPriorEvidence(ctx, []map[string]interface{}{{"role": "user", "content": "What does it mean?"}}, 1)
	if err != nil || !strings.Contains(messages[0]["content"].(string), "patient evidence") {
		t.Fatal(messages, err)
	}
	stored, err := db.GetMessages(1)
	if err != nil || len(stored) != 0 {
		t.Fatal("evidence inserted as an invalid/visible message", stored, err)
	}
	if err = db.DeleteConversation(1); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveToolEvidence(ctx, 1, "read", "{}", "late result"); err == nil {
		t.Fatal("evidence recreated after conversation deletion")
	}
	rows, err := db.ToolEvidence(ctx, 1)
	if err != nil || len(rows) != 0 {
		t.Fatal("evidence survived deletion", rows, err)
	}
}
func TestKnowledgeSearchBalancesCollections(t *testing.T) {
	ctx := modelTestContext(t)
	for i := 0; i < 25; i++ {
		if _, err := db.DB.Exec("INSERT INTO islamqa(slug,category,question,answer) VALUES(?,'test','mercy','mercy')", fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.DB.Exec("INSERT INTO quran(chapter,chapter_name,verse,text) VALUES(1,'Opening',1,'mercy')"); err != nil {
		t.Fatal(err)
	}
	items, err := searchReferenceCollections(ctx, "mercy", "", 2)
	if err != nil || len(items) != 2 {
		t.Fatal(items, err)
	}
	kinds := map[interface{}]bool{}
	for _, item := range items {
		kinds[item["Kind"]] = true
	}
	if !kinds["quran"] || !kinds["islamqa"] {
		t.Fatal("early collection crowded out another source", items)
	}
}
func TestReadableDeduplicatedCitations(t *testing.T) {
	citations := toolCitations(`{"source":"Quran","url":"https://aslam.org/quran/2/153","resource":{"Title":"Al-Baqarah 2:153"}}`)
	used := []ToolUsage{{Name: "read", Input: `{"path":"/quran/2/153"}`, Citations: citations}, {Name: "read", Citations: citations}, {Name: "read", Failed: true, Citations: []Citation{{"bad", "https://aslam.org/quran/1/1"}}}}
	footer := formatSourcesFooter(used)
	if strings.Count(footer, "https://aslam.org/quran/2/153") != 1 || !strings.Contains(footer, "[Al-Baqarah 2:153]") || strings.Contains(footer, "path") || strings.Contains(footer, "bad") {
		t.Fatal(footer)
	}
	for _, url := range []string{"javascript:alert(1)", "https://evil.test/quran/1/1", "/notes/1"} {
		if len(toolCitations(fmt.Sprintf(`{"url":%q}`, url))) != 0 {
			t.Fatal("unsafe citation", url)
		}
	}
}
func TestPrematureModelStreamIsError(t *testing.T) {
	ctx := modelTestContext(t)
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	for _, body := range []string{"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n", "data: {\"type\":\"error\",\"error\":{\"message\":\"overloaded\"}}\n\n"} {
		http.DefaultTransport = cancelTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})
		if _, _, err := callAnthropicStream(ctx, nil, "test", nil); err == nil {
			t.Fatal("incomplete stream treated as success")
		}
	}
}
