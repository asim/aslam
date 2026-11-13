package server

import (
	"encoding/json"
	"testing"
)

func TestContentBlockPreservesThinkingFields(t *testing.T) {
	raw := []byte(`{
		"content": [
			{
				"type": "thinking",
				"thinking": "",
				"signature": "signed-value"
			},
			{
				"type": "redacted_thinking",
				"data": "encrypted-value"
			},
			{
				"type": "tool_use",
				"id": "tool-1",
				"name": "search",
				"input": {"query": "test"}
			}
		],
		"stop_reason": "tool_use"
	}`)

	var response anthropicResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	encoded, err := json.Marshal(response.Content)
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}

	var blocks []map[string]interface{}
	if err := json.Unmarshal(encoded, &blocks); err != nil {
		t.Fatalf("unmarshal encoded content: %v", err)
	}

	got, ok := blocks[0]["thinking"]
	if !ok {
		t.Fatal("empty thinking field was omitted")
	}
	if got != "" {
		t.Errorf("thinking = %v, want empty string", got)
	}
	if got := blocks[0]["signature"]; got != "signed-value" {
		t.Errorf("signature = %v, want signed-value", got)
	}
	if got := blocks[1]["data"]; got != "encrypted-value" {
		t.Errorf("redacted data = %v, want encrypted-value", got)
	}
}

func TestToolInputSerialization(t *testing.T) {
	for _, raw := range []string{
		`{"type":"tool_use","id":"tool-1","name":"collections","input":{}}`,
		`{"type":"tool_use","id":"tool-1","name":"collections","input":null}`,
		`{"type":"tool_use","id":"tool-1","name":"search","input":{"query":"patience"}}`,
		`{"type":"text","text":"Answer"}`,
	} {
		var block contentBlock
		if err := json.Unmarshal([]byte(raw), &block); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(block)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if block.Type == "tool_use" {
			var input map[string]interface{}
			if err := json.Unmarshal(fields["input"], &input); err != nil || input == nil {
				t.Fatalf("required object absent: %s", encoded)
			}
			if block.Name == "search" && input["query"] != "patience" {
				t.Fatal("lost arguments")
			}
		} else if _, ok := fields["input"]; ok {
			t.Fatalf("tool field on text: %s", encoded)
		}
	}
}
