package main

import (
	"encoding/json"
	"testing"
)

func TestContentBlockPreservesThinkingFields(t *testing.T) {
	raw := []byte(`{
		"content": [
			{
				"type": "thinking",
				"thinking": "reasoning text",
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

	if got := blocks[0]["thinking"]; got != "reasoning text" {
		t.Errorf("thinking = %v, want reasoning text", got)
	}
	if got := blocks[0]["signature"]; got != "signed-value" {
		t.Errorf("signature = %v, want signed-value", got)
	}
	if got := blocks[1]["data"]; got != "encrypted-value" {
		t.Errorf("redacted data = %v, want encrypted-value", got)
	}
}
