package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WikiSearch searches Wikipedia and returns summaries
func WikiSearch(query string) (string, error) {
	// Search for pages matching the query
	searchURL := fmt.Sprintf(
		"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=%s&format=json&srlimit=3",
		url.QueryEscape(query),
	)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(searchURL)
	if err != nil {
		return "", fmt.Errorf("search failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var searchResult struct {
		Query struct {
			Search []struct {
				Title   string `json:"title"`
				PageID  int    `json:"pageid"`
				Snippet string `json:"snippet"`
			} `json:"search"`
		} `json:"query"`
	}

	if err := json.Unmarshal(body, &searchResult); err != nil {
		return "", fmt.Errorf("failed to parse search results: %w", err)
	}

	if len(searchResult.Query.Search) == 0 {
		return "No Wikipedia articles found for this query.", nil
	}

	// Get summaries for top results
	var results []string
	for _, page := range searchResult.Query.Search {
		summary, err := getWikiSummary(page.Title)
		if err != nil {
			continue
		}
		results = append(results, fmt.Sprintf("## %s\n\n%s\n", page.Title, summary))
	}

	if len(results) == 0 {
		return "Found articles but couldn't retrieve summaries.", nil
	}

	return strings.Join(results, "\n---\n\n"), nil
}

func getWikiSummary(title string) (string, error) {
	summaryURL := fmt.Sprintf(
		"https://en.wikipedia.org/api/rest_v1/page/summary/%s",
		url.PathEscape(title),
	)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", summaryURL, nil)
	req.Header.Set("User-Agent", "Aslam/1.0 (personal assistant)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	var summary struct {
		Title       string `json:"title"`
		Extract     string `json:"extract"`
		Description string `json:"description"`
		ContentURLs struct {
			Desktop struct {
				Page string `json:"page"`
			} `json:"desktop"`
		} `json:"content_urls"`
	}

	if err := json.Unmarshal(body, &summary); err != nil {
		return "", err
	}

	result := summary.Extract
	if summary.ContentURLs.Desktop.Page != "" {
		result += fmt.Sprintf("\n\nSource: %s", summary.ContentURLs.Desktop.Page)
	}

	return result, nil
}
