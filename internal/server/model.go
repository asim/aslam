package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"aslam/db"
	"aslam/internal/tools"
)

var systemPromptTemplate = `You are an Islamic knowledge assistant. Your purpose is to help Muslims seek, understand, and save Islamic knowledge from authentic sources.

You have access to a knowledge base containing the Quran, Sahih al-Bukhari, 99 Names of Allah, scholarly Q&A (IslamQA), Imam Al-Ghazali's Ihya Ulum al-Din, Riyad us-Salihin, daily adhkar, and Quranic Arabic vocabulary — over 40,000 indexed records from authentic Islamic sources.

SCOPE:
You answer questions about Islam, the Quran, Hadith, fiqh, aqeedah, history, manners, spirituality, and daily practice. When a question touches everyday life (finance, food, health, relationships, parenting), answer from an Islamic perspective using the sources available to you.

Politely decline questions that have no Islamic relevance. You are not a general-purpose assistant. If someone asks about programming, sports scores, or unrelated topics, respond briefly: "I'm here to help with Islamic knowledge. You might find a general search engine more helpful for that." Do not answer the question.

TOOLS:
- search: Search the full knowledge base (Quran, Hadith, Names, IslamQA, Ghazali, Seerah, Adhkar, Salihin, notes). Seerah results come from The Sealed Nectar by Safiur Rahman al-Mubarakpuri, translated by Issam Diab; cite the specific page and distinguish biographical reports from Quran and hadith.
- reminder: Semantic search across Quran, Hadith, and Names of Allah via the reminder API.
- islamqa: Search IslamQA for scholarly answers.
- ghazali: Search Imam Al-Ghazali's Ihya Ulum al-Din.
- adhkar: Search duas and dhikr.
- salihin: Search Riyad us-Salihin.
- fetch: Fetch a URL — use only for Islamic content (articles, fatawa, lectures).
- web_search: Search the web — use only for Islamic topics (scholar opinions, Islamic history, halal/haram rulings).
- note_add / note_update: Save knowledge the user wants to keep.

Always search the knowledge base before searching the web. Prefer authentic sourced content over web results.

QUERY REFORMULATION:
The knowledge base uses keyword search (FTS), not semantic search. When calling search, islamqa, ghazali, adhkar, or salihin tools:
- Reformulate natural language into search keywords
- Use synonyms: "anger" → also try "wrath", "rage"
- Include Arabic transliterations: "patience" → also try "sabr"
- Include related Islamic concepts: "dealing with loss" → try "patience adversity", "qadr"
- Strip filler words: "how do I deal with anger" → "controlling anger"
- Call a tool multiple times with different queries rather than missing content
- For the reminder tool (semantic search), pass natural language directly

TONE:
- Be concise and direct. Cite your sources (which surah, which hadith, which scholar).
- Do not pretend to be a scholar. Say "scholars have said" or "according to IslamQA" — never issue rulings yourself.
- When there is scholarly disagreement, present the main positions fairly.
- Do not add excessive Islamic greetings or phrases unless the user does first.
- Do not be preachy. Present knowledge; let the user reflect.
- Be humble. You are a tool to help find knowledge, not a source of authority.`

var systemPrompt string

func init() {
	systemPrompt = systemPromptTemplate
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func formatSourcesFooter(toolsUsed []ToolUsage) string {
	if len(toolsUsed) == 0 {
		return ""
	}

	seen := make(map[string]bool)
	var sources strings.Builder
	sources.WriteString("\n\n---\n**Sources:**\n")
	for _, tool := range toolsUsed {
		key := tool.Name + ":" + tool.Input
		if seen[key] {
			continue
		}
		seen[key] = true
		sources.WriteString(fmt.Sprintf("- %s: `%s`\n", tool.Name, tool.Input))
	}

	return sources.String()
}

func formatResponseWithSources(response string, toolsUsed []ToolUsage) string {
	return response + formatSourcesFooter(toolsUsed)
}

// UserContext contains info about the current user for personalization
type UserContext struct {
	Email          string
	Name           string
	ConversationID int64
}

var currentUserContext *UserContext

// ToolUsage tracks a single tool call and its result
type ToolUsage struct {
	Name   string
	Input  string
	Output string
}

// buildAPIMessages converts stored conversation messages into the message
// list sent to the Anthropic API. "context" and "tool" messages are replayed
// as assistant turns so the model can reference them. Any context messages
// that appear before the first user message (e.g. the page content a chat was
// opened from) are folded into the system prompt instead, since the API
// requires the first message to use the user role. It returns the API messages
// and any text to append to the system prompt.
func buildAPIMessages(messages []db.Message) ([]map[string]interface{}, string) {
	var apiMessages []map[string]interface{}
	var pageContext []string
	seenUser := false
	for _, m := range messages {
		// "system" messages carry the page/seed context a chat was opened
		// with (e.g. the verse or hadith the user clicked "Chat" on). They are
		// folded into the system prompt regardless of position, so the message
		// list always begins with a real user turn and never ends on a stray
		// assistant turn.
		if m.Role == "system" {
			if strings.TrimSpace(m.Content) != "" {
				pageContext = append(pageContext, m.Content)
			}
			continue
		}
		// Legacy: older databases allowed the "context" role for page context
		// stored before the first user turn. Fold those in the same way.
		if !seenUser && m.Role == "context" {
			if strings.TrimSpace(m.Content) != "" {
				pageContext = append(pageContext, m.Content)
			}
			continue
		}
		if m.Role == "user" {
			seenUser = true
		}
		role := m.Role
		if role == "context" || role == "tool" {
			role = "assistant"
		}
		apiMessages = append(apiMessages, map[string]interface{}{
			"role":    role,
			"content": m.Content,
		})
	}

	var contextPrompt string
	if len(pageContext) > 0 {
		contextPrompt = "\n\nThe user opened this chat while reading the following content and is likely asking about it. Use it as the primary context for their questions:\n\n" + strings.Join(pageContext, "\n\n")
	}
	return apiMessages, contextPrompt
}

func generateResponse(messages []db.Message, convID int64) (string, []ToolUsage, error) {
	return generateResponseWithProgress(messages, convID, nil)
}

func generateResponseWithProgress(messages []db.Message, convID int64, onTool func(string)) (string, []ToolUsage, error) {
	return generateResponseWithProgressContext(context.Background(), messages, convID, onTool)
}

func generateResponseWithProgressContext(ctx context.Context, messages []db.Message, convID int64, onTool func(string)) (string, []ToolUsage, error) {
	var toolsUsed []ToolUsage
	if anthropicKey == "" {
		return "", nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	// Build system prompt with user context
	fullSystemPrompt := systemPrompt
	if currentUserContext != nil && currentUserContext.Email != "" {
		fullSystemPrompt += fmt.Sprintf("\n\nCurrent user: %s", currentUserContext.Email)
		if currentUserContext.Name != "" {
			fullSystemPrompt += fmt.Sprintf(" (%s)", currentUserContext.Name)
		}
		fullSystemPrompt += "\nIf the user asks you to send them an email, use this address."
	}

	// Build messages for API
	apiMessages, contextPrompt := buildAPIMessages(messages)
	fullSystemPrompt += contextPrompt

	// Tool loop - keep calling until we get a final response
	for i := 0; i < 10; i++ { // Max 10 tool calls
		result, err := callAnthropic(ctx, apiMessages, fullSystemPrompt)
		if err != nil {
			return "", toolsUsed, err
		}

		// Check if we need to handle tool use
		if result.StopReason == "tool_use" {
			// Add assistant message with tool use
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "assistant",
				"content": result.Content,
			})

			// Process tool calls and build tool results
			var toolResults []map[string]interface{}
			var contextLines []string
			for _, block := range result.Content {
				if block.Type == "tool_use" {
					if err := ctx.Err(); err != nil {
						return "", toolsUsed, err
					}
					inputJSON, _ := json.Marshal(block.Input)
					log.Printf("Tool call: %s(%v)", block.Name, block.Input)
					if onTool != nil {
						onTool(block.Name)
					}
					toolResult, err := tools.ExecuteTool(block.Name, block.Input)
					if err != nil {
						toolResult = fmt.Sprintf("Error: %v", err)
					}

					// Track tool usage
					toolsUsed = append(toolsUsed, ToolUsage{
						Name:   block.Name,
						Input:  string(inputJSON),
						Output: truncateString(toolResult, 500),
					})

					toolResults = append(toolResults, map[string]interface{}{
						"type":        "tool_result",
						"tool_use_id": block.ID,
						"content":     toolResult,
					})

					contextLines = append(contextLines, fmt.Sprintf("[%s(%s): %s]", block.Name, string(inputJSON), truncateString(toolResult, 1000)))
				}
			}

			// Add tool results as user message
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})

			// Save a text summary so the AI can reference it in follow-up turns
			if convID > 0 && len(contextLines) > 0 {
				db.AddMessage(convID, "context", strings.Join(contextLines, "\n"))
			}
			continue
		}

		// Extract text response
		var textResponse string
		for _, block := range result.Content {
			if block.Type == "text" {
				textResponse = block.Text
				break
			}
		}

		// If no text but we had tool calls that succeeded, return a default message
		if textResponse == "" {
			return "Done.", toolsUsed, nil
		}
		return textResponse, toolsUsed, nil
	}

	return "", toolsUsed, fmt.Errorf("too many tool calls")
}

func generateResponseStreaming(ctx context.Context, messages []db.Message, convID int64, onText func(string)) (string, []ToolUsage, error) {
	var toolsUsed []ToolUsage
	if anthropicKey == "" {
		return "", nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}

	fullSystemPrompt := systemPrompt
	if currentUserContext != nil && currentUserContext.Email != "" {
		fullSystemPrompt += fmt.Sprintf("\n\nCurrent user: %s", currentUserContext.Email)
		if currentUserContext.Name != "" {
			fullSystemPrompt += fmt.Sprintf(" (%s)", currentUserContext.Name)
		}
	}

	apiMessages, contextPrompt := buildAPIMessages(messages)
	fullSystemPrompt += contextPrompt

	for i := 0; i < 10; i++ {
		result, textSoFar, err := callAnthropicStream(ctx, apiMessages, fullSystemPrompt, onText)
		if err != nil {
			return "", toolsUsed, err
		}

		if result.StopReason == "tool_use" {
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "assistant",
				"content": result.Content,
			})

			var toolResults []map[string]interface{}
			var contextLines []string
			for _, block := range result.Content {
				if block.Type == "tool_use" {
					if err := ctx.Err(); err != nil {
						return "", toolsUsed, err
					}
					inputJSON, _ := json.Marshal(block.Input)
					log.Printf("Tool call: %s(%v)", block.Name, block.Input)
					if onText != nil {
						onText("\n!tool:" + block.Name + "\n")
					}
					toolResult, err := tools.ExecuteTool(block.Name, block.Input)
					if err != nil {
						toolResult = fmt.Sprintf("Error: %v", err)
					}
					toolsUsed = append(toolsUsed, ToolUsage{
						Name:   block.Name,
						Input:  string(inputJSON),
						Output: truncateString(toolResult, 500),
					})
					toolResults = append(toolResults, map[string]interface{}{
						"type":        "tool_result",
						"tool_use_id": block.ID,
						"content":     toolResult,
					})
					contextLines = append(contextLines, fmt.Sprintf("[%s(%s): %s]", block.Name, string(inputJSON), truncateString(toolResult, 1000)))
				}
			}
			apiMessages = append(apiMessages, map[string]interface{}{
				"role":    "user",
				"content": toolResults,
			})
			if convID > 0 && len(contextLines) > 0 {
				db.AddMessage(convID, "context", strings.Join(contextLines, "\n"))
			}
			continue
		}

		if textSoFar == "" {
			return "Done.", toolsUsed, nil
		}
		return textSoFar, toolsUsed, nil
	}
	return "", toolsUsed, fmt.Errorf("too many tool calls")
}

func callAnthropicStream(ctx context.Context, apiMessages []map[string]interface{}, sysPrompt string, onText func(string)) (*anthropicResponse, string, error) {
	reqBody := map[string]interface{}{
		"model":      anthropicModel,
		"max_tokens": 4096,
		"tools":      tools.GetTools(),
		"system":     sysPrompt,
		"messages":   apiMessages,
		"stream":     true,
	}

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse SSE stream from Anthropic
	var fullText strings.Builder
	var contentBlocks []contentBlock
	var currentToolInput strings.Builder
	var currentThinking strings.Builder
	var currentSignature strings.Builder
	var currentToolID, currentToolName, currentBlockType, currentRedactedData string
	stopReason := ""

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}

		var event struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type      string          `json:"type"`
				ID        string          `json:"id"`
				Name      string          `json:"name"`
				Text      string          `json:"text"`
				Thinking  string          `json:"thinking"`
				Signature string          `json:"signature"`
				Data      string          `json:"data"`
				Input     json.RawMessage `json:"input"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				Signature   string `json:"signature"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta"`
			Message struct {
				StopReason string `json:"stop_reason"`
			} `json:"message"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		switch event.Type {
		case "content_block_start":
			currentBlockType = event.ContentBlock.Type
			switch currentBlockType {
			case "tool_use":
				currentToolID = event.ContentBlock.ID
				currentToolName = event.ContentBlock.Name
				currentToolInput.Reset()
			case "thinking":
				currentThinking.Reset()
				currentSignature.Reset()
				currentThinking.WriteString(event.ContentBlock.Thinking)
				currentSignature.WriteString(event.ContentBlock.Signature)
			case "redacted_thinking":
				currentRedactedData = event.ContentBlock.Data
			}
		case "content_block_delta":
			if event.Delta.Type == "text_delta" && event.Delta.Text != "" {
				fullText.WriteString(event.Delta.Text)
				if onText != nil {
					onText(event.Delta.Text)
				}
			} else if event.Delta.Type == "input_json_delta" {
				currentToolInput.WriteString(event.Delta.PartialJSON)
			} else if event.Delta.Type == "thinking_delta" {
				currentThinking.WriteString(event.Delta.Thinking)
			} else if event.Delta.Type == "signature_delta" {
				currentSignature.WriteString(event.Delta.Signature)
			}
		case "content_block_stop":
			switch currentBlockType {
			case "tool_use":
				var input map[string]interface{}
				json.Unmarshal([]byte(currentToolInput.String()), &input)
				contentBlocks = append(contentBlocks, contentBlock{
					Type:  "tool_use",
					ID:    currentToolID,
					Name:  currentToolName,
					Input: input,
				})
				currentToolName = ""
			case "thinking":
				thinking := currentThinking.String()
				signature := currentSignature.String()
				contentBlocks = append(contentBlocks, contentBlock{
					Type:      "thinking",
					Thinking:  &thinking,
					Signature: &signature,
				})
			case "redacted_thinking":
				data := currentRedactedData
				contentBlocks = append(contentBlocks, contentBlock{
					Type: "redacted_thinking",
					Data: &data,
				})
			case "text":
				if fullText.Len() > 0 {
					contentBlocks = append(contentBlocks, contentBlock{
						Type: "text",
						Text: fullText.String(),
					})
				}
			}
			currentBlockType = ""
		case "message_delta":
			if event.Delta.StopReason != "" {
				stopReason = event.Delta.StopReason
			}
		}
	}

	// A stopped scanner may mean cancellation or a failed body read, not a
	// completed response. Never report partial output as a successful answer.
	if err := ctx.Err(); err != nil {
		return nil, fullText.String(), err
	}
	if err := scanner.Err(); err != nil {
		return nil, fullText.String(), fmt.Errorf("read model stream: %w", err)
	}

	return &anthropicResponse{
		Content:    contentBlocks,
		StopReason: stopReason,
	}, fullText.String(), nil
}

type anthropicResponse struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
}

type contentBlock struct {
	Type      string                 `json:"type"`
	Text      string                 `json:"text,omitempty"`
	Thinking  *string                `json:"thinking,omitempty"`
	Signature *string                `json:"signature,omitempty"`
	Data      *string                `json:"data,omitempty"`
	ID        string                 `json:"id,omitempty"`
	Name      string                 `json:"name,omitempty"`
	Input     map[string]interface{} `json:"input,omitempty"`
}

func callAnthropic(ctx context.Context, apiMessages []map[string]interface{}, sysPrompt string) (*anthropicResponse, error) {
	reqBody := map[string]interface{}{
		"model":      anthropicModel,
		"max_tokens": 4096,
		"tools":      tools.GetTools(),
		"system":     sysPrompt,
		"messages":   apiMessages,
	}

	jsonBody, _ := json.Marshal(reqBody)
	log.Printf("Sending to Anthropic: system prompt len=%d, messages=%d", len(sysPrompt), len(apiMessages))
	if len(sysPrompt) > 200 {
		log.Printf("System prompt starts: %s...", systemPrompt[:200])
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", anthropicKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var result anthropicResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
