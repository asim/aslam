package tools

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// FetchURL fetches a URL and returns the text content
func FetchURL(url string) (string, error) {
	// Ensure URL has scheme
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Aslam/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")

	// Limit read to 1MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read: %w", err)
	}

	// If HTML, extract text
	if strings.Contains(contentType, "text/html") {
		return extractText(string(body)), nil
	}

	// For other text types, return as-is (truncated)
	if strings.Contains(contentType, "text/") || strings.Contains(contentType, "application/json") {
		text := string(body)
		if len(text) > 10000 {
			text = text[:10000] + "\n... (truncated)"
		}
		return text, nil
	}

	return fmt.Sprintf("[Binary content: %s, %d bytes]", contentType, len(body)), nil
}

// extractText extracts readable text from HTML
func extractText(htmlContent string) string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return htmlContent
	}

	var sb strings.Builder
	var extract func(*html.Node)

	extract = func(n *html.Node) {
		// Skip script, style, and other non-content tags
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "noscript", "iframe", "svg", "path":
				return
			case "p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr":
				sb.WriteString("\n")
			}
		}

		if n.Type == html.TextNode {
			text := strings.TrimSpace(n.Data)
			if text != "" {
				sb.WriteString(text)
				sb.WriteString(" ")
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}

	extract(doc)

	// Clean up whitespace
	result := sb.String()
	result = regexp.MustCompile(`\n\s*\n`).ReplaceAllString(result, "\n\n")
	result = strings.TrimSpace(result)

	// Truncate if too long
	if len(result) > 10000 {
		result = result[:10000] + "\n... (truncated)"
	}

	return result
}
