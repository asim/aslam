package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type islamResponse struct {
	Answer     string      `json:"answer"`
	Query      string      `json:"q"`
	References []reference `json:"references"`
}

type reference struct {
	Text     string            `json:"text"`
	Score    float64           `json:"score"`
	Metadata map[string]string `json:"metadata"`
}

// SearchIslam queries the Islamic knowledge API for Quran, Hadith, and names of Allah
func SearchIslam(query string) (string, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"q": query,
	})

	client := &http.Client{
		Timeout: 120 * time.Second, // Long timeout - uses Fanar which is slow
	}

	req, err := http.NewRequest("POST", "https://reminder.dev/api/search", bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var result islamResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return string(body), nil
	}

	return formatIslamResponse(result), nil
}

func formatIslamResponse(r islamResponse) string {
	var sb strings.Builder

	// Clean HTML from answer
	answer := stripHTML(r.Answer)
	sb.WriteString("SUMMARY:\n")
	sb.WriteString(answer)
	sb.WriteString("\n\nREFERENCES:\n")

	// Group by source and show top references
	shown := 0
	for _, ref := range r.References {
		if shown >= 10 {
			break
		}

		source := ref.Metadata["source"]
		var citation string

		switch source {
		case "quran":
			chapter := ref.Metadata["chapter"]
			verse := ref.Metadata["verse"]
			name := ref.Metadata["name"]
			citation = fmt.Sprintf("Quran %s:%s (%s)", chapter, verse, name)
		case "bukhari":
			book := ref.Metadata["book"]
			info := ref.Metadata["info"]
			by := ref.Metadata["by"]
			citation = fmt.Sprintf("Sahih Bukhari - %s, %s, %s", book, info, by)
		case "names":
			arabic := ref.Metadata["arabic"]
			english := ref.Metadata["english"]
			citation = fmt.Sprintf("Names of Allah: %s (%s)", english, arabic)
		default:
			citation = source
		}

		sb.WriteString(fmt.Sprintf("\n[%s]\n", citation))
		sb.WriteString(ref.Text)
		sb.WriteString("\n")
		shown++
	}

	return sb.String()
}

func stripHTML(s string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	s = re.ReplaceAllString(s, "")
	// Decode common HTML entities
	s = strings.ReplaceAll(s, "&ldquo;", "\"")
	s = strings.ReplaceAll(s, "&rdquo;", "\"")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	return strings.TrimSpace(s)
}
