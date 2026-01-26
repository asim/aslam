package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func getBraveAPIKey() string {
	return os.Getenv("BRAVE_API_KEY")
}

// BraveSearchResponse represents the Brave Search API response
type BraveSearchResponse struct {
	Web struct {
		Results []struct {
			Title       string `json:"title"`
			URL         string `json:"url"`
			Description string `json:"description"`
		} `json:"results"`
	} `json:"web"`
}

// WebSearch performs a web search using Brave Search API
func WebSearch(query string) (string, error) {
	apiKey := getBraveAPIKey()
	if apiKey == "" {
		return "", fmt.Errorf("BRAVE_API_KEY not set")
	}

	// Build request
	searchURL := fmt.Sprintf("https://api.search.brave.com/res/v1/web/search?q=%s&count=10",
		url.QueryEscape(query))

	req, err := http.NewRequest("GET", searchURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", apiKey)

	// Execute request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("search request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("search failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var searchResp BraveSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(searchResp.Web.Results) == 0 {
		return "No results found.", nil
	}

	// Format results
	var sb strings.Builder
	for i, result := range searchResp.Web.Results {
		sb.WriteString(fmt.Sprintf("%d. %s\n   %s\n   %s\n\n",
			i+1, result.Title, result.URL, result.Description))
	}

	return sb.String(), nil
}
