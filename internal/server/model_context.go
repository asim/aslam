package server

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

const continueAnswer = "Continue the interrupted answer exactly where it stopped, without repeating earlier text. Finish the answer and citations."

func excerpt(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	marker := "\n[Excerpt shortened to fit context; use read with text_offset/text_limit for omitted source text.]\n"
	keep := limit - len(marker)
	if keep < 2 {
		return "[omitted]"
	}
	head := keep * 3 / 4
	tail := len(s) - (keep - head)
	for head > 0 && !utf8.RuneStart(s[head]) {
		head--
	}
	for tail < len(s) && !utf8.RuneStart(s[tail]) {
		tail++
	}
	return s[:head] + marker + s[tail:]
}

// Work on a copy: persistence and the full tool history remain intact. Prune
// complete old turns and tool exchanges, never orphan tool_result IDs.
func prepareModelBody(body map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if len(raw) <= 64<<10 {
		return raw, nil
	}
	var copy map[string]interface{}
	if err = json.Unmarshal(raw, &copy); err != nil {
		return nil, err
	}
	messages, _ := copy["messages"].([]interface{})
	encode := func() []byte { copy["messages"] = messages; b, _ := json.Marshal(copy); return b }
	realUser := func(v interface{}) bool {
		m, ok := v.(map[string]interface{})
		if !ok || m["role"] != "user" {
			return false
		}
		s, ok := m["content"].(string)
		return ok && s != continueAnswer
	}
	// Old conversation turns first; retain the entire current question/tool chain.
	for len(encode()) > 64<<10 {
		next := -1
		for i := 1; i < len(messages); i++ {
			if realUser(messages[i]) {
				next = i
				break
			}
		}
		if next < 0 {
			break
		}
		messages = messages[next:]
	}
	// Large source outputs are explicitly excerpted. read supports text offsets.
	for _, limit := range []int{16000, 8000, 4000, 2000, 1000} {
		if len(encode()) <= 64<<10 {
			break
		}
		for _, v := range messages {
			m := v.(map[string]interface{})
			blocks, ok := m["content"].([]interface{})
			if !ok {
				continue
			}
			for _, v := range blocks {
				b, ok := v.(map[string]interface{})
				if !ok {
					continue
				}
				if b["type"] == "tool_result" {
					if s, ok := b["content"].(string); ok {
						b["content"] = excerpt(s, limit)
					}
				}
			}
		}
	}
	if len(encode()) > 64<<10 {
		if s, ok := copy["system"].(string); ok {
			copy["system"] = excerpt(s, 16000)
		}
	}
	// Drop oldest complete exchanges from the current turn only when necessary.
	for len(encode()) > 64<<10 && len(messages) > 3 {
		removed := false
		for i := 1; i+1 < len(messages)-1; i++ {
			a := messages[i].(map[string]interface{})
			b := messages[i+1].(map[string]interface{})
			if a["role"] == "assistant" && b["role"] == "user" {
				messages = append(messages[:i], messages[i+2:]...)
				removed = true
				break
			}
		}
		if !removed {
			break
		}
	}
	if len(encode()) > 64<<10 {
		// Keep the end (the current question) when prior evidence is very large.
		for _, v := range messages {
			m := v.(map[string]interface{})
			if s, ok := m["content"].(string); ok && len(s) > 16000 {
				m["content"] = excerpt(s, 16000)
			}
		}
	}
	raw = encode()
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("question exceeds the supported context size")
	}
	return raw, nil
}
