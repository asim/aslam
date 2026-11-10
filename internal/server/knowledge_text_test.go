package server

import (
	"aslam/data"
	"aslam/db"
	"encoding/json"
	"strings"
	"testing"
)

func TestLongTafsirPagesFitModelBudget(t *testing.T) {
	ctx := modelTestContext(t)
	if err := db.ImportTafsir(data.Tafsir); err != nil {
		t.Fatal(err)
	}
	passage, err := db.GetTafsir(ctx, 1, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(passage.Text) <= 64<<10 {
		t.Fatal("fixture no longer exercises oversized passage")
	}
	var reconstructed strings.Builder
	messages := []map[string]interface{}{{"role": "user", "content": "Explain this passage"}}
	offset := 0
	for pageNumber := 0; ; pageNumber++ {
		output, err := executeChatTool(ctx, "read", map[string]interface{}{"path": "/tafsir/ibn-kathir/1/6", "text_offset": offset})
		if err != nil {
			t.Fatal(err)
		}
		var page struct {
			Resource map[string]interface{} `json:"resource"`
			TextPage struct {
				Next *int `json:"next"`
			} `json:"text_page"`
		}
		if err = json.Unmarshal([]byte(output), &page); err != nil {
			t.Fatal(err)
		}
		if _, ok := page.Resource["HTML"]; ok {
			t.Fatal("duplicate HTML in model result")
		}
		reconstructed.WriteString(page.Resource["Content"].(string))
		messages = append(messages, map[string]interface{}{"role": "assistant", "content": []map[string]interface{}{{"type": "tool_use", "id": "read", "name": "read", "input": map[string]interface{}{"path": "/tafsir/ibn-kathir/1/6", "text_offset": offset}}}}, map[string]interface{}{"role": "user", "content": []map[string]interface{}{{"type": "tool_result", "tool_use_id": "read", "content": output}}})
		body, err := prepareModelBody(map[string]interface{}{"system": systemPrompt, "tools": chatTools(), "messages": messages})
		if err != nil || len(body) > 64<<10 {
			t.Fatalf("page %d bytes=%d err=%v", pageNumber, len(body), err)
		}
		if page.TextPage.Next == nil {
			break
		}
		if *page.TextPage.Next <= offset {
			t.Fatal("pagination did not advance")
		}
		offset = *page.TextPage.Next
	}
	if reconstructed.String() != passage.Text {
		t.Fatal("pagination lost or duplicated source text")
	}
}
func TestModelPackingKeepsQuestion(t *testing.T) {
	body := map[string]interface{}{"system": "instructions", "messages": []map[string]interface{}{{"role": "user", "content": strings.Repeat("old ", 20000)}, {"role": "assistant", "content": "old answer"}, {"role": "user", "content": "current question"}}}
	raw, err := prepareModelBody(body)
	if err != nil || !strings.Contains(string(raw), "current question") || len(raw) > 64<<10 {
		t.Fatal(string(raw), err)
	}
	if len(body["messages"].([]map[string]interface{})) != 3 {
		t.Fatal("mutated stored history")
	}
}
