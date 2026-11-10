package server

import (
	"context"
	"fmt"
	"strings"
)

// Retry the original request: truncated tool input must never enter history or
// reach a tool. These attempts share the caller's question reservation/context.
const maxToolOutputTokens = 16384

func truncatedToolCall(result *anthropicResponse) bool {
	if result == nil || result.StopReason != "max_tokens" {
		return false
	}
	for _, block := range result.Content {
		if block.Type == "tool_use" {
			return true
		}
	}
	return false
}

func callAnthropic(ctx context.Context, messages []map[string]interface{}, system string) (*anthropicResponse, error) {
	for budget := 2048; ; budget *= 2 {
		result, err := callAnthropicAttempt(ctx, messages, system, budget)
		if err != nil || !truncatedToolCall(result) {
			return result, err
		}
		if budget >= maxToolOutputTokens {
			return nil, fmt.Errorf("model tool input exceeds output budget")
		}
	}
}

func callAnthropicStream(ctx context.Context, messages []map[string]interface{}, system string, onText func(string)) (*anthropicResponse, string, error) {
	var initialText string
	for budget := 2048; ; budget *= 2 {
		// Keep normal responses live. Buffer exceptional retries so that a repeated
		// tool preamble is not displayed again before its completed tool call.
		callback := onText
		if budget > 2048 {
			callback = nil
		}
		result, text, err := callAnthropicStreamAttempt(ctx, messages, system, callback, budget)
		if err != nil {
			return result, text, err
		}
		if !truncatedToolCall(result) {
			if budget > 2048 && onText != nil {
				if strings.HasPrefix(text, initialText) {
					onText(strings.TrimPrefix(text, initialText))
				} else if text != "" {
					onText("\n" + text)
				}
			}
			return result, text, nil
		}
		if budget == 2048 {
			initialText = text
		}
		if budget >= maxToolOutputTokens {
			return nil, text, fmt.Errorf("model tool input exceeds output budget")
		}
	}
}
