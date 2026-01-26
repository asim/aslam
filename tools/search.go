package tools

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

var (
	browserCtx    context.Context
	browserCancel context.CancelFunc
	tabCtx        context.Context
	tabCancel     context.CancelFunc
	searchMu      sync.Mutex
	browserReady  bool
)

func initBrowser() error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath("/usr/bin/google-chrome-stable"),
		chromedp.Flag("headless", "new"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.UserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)

	allocCtx, _ := chromedp.NewExecAllocator(context.Background(), opts...)
	browserCtx, browserCancel = chromedp.NewContext(allocCtx)
	
	// Create single tab for all searches
	tabCtx, tabCancel = chromedp.NewContext(browserCtx)
	
	// Start the browser
	if err := chromedp.Run(tabCtx, chromedp.Navigate("about:blank")); err != nil {
		return err
	}
	
	browserReady = true
	log.Println("Browser initialized for web search")
	return nil
}

// WebSearch performs a web search using headless Chrome
func WebSearch(query string) (string, error) {
	searchMu.Lock()
	defer searchMu.Unlock()

	// Initialize browser if needed
	if !browserReady {
		if err := initBrowser(); err != nil {
			return "", fmt.Errorf("failed to init browser: %w", err)
		}
	}

	// Add timeout for this search
	ctx, cancel := context.WithTimeout(tabCtx, 30*time.Second)
	defer cancel()

	// Use DuckDuckGo
	searchURL := fmt.Sprintf("https://duckduckgo.com/?q=%s", strings.ReplaceAll(query, " ", "+"))

	var results string
	err := chromedp.Run(ctx,
		chromedp.Navigate(searchURL),
		chromedp.Sleep(5*time.Second), // Wait for JS to render
		chromedp.Text("body", &results, chromedp.ByQuery),
	)
	if err != nil {
		// Browser might have died, reset it
		browserReady = false
		return "", fmt.Errorf("search failed: %w", err)
	}

	if results == "" {
		return "No results found.", nil
	}

	// Trim to reasonable length
	if len(results) > 4000 {
		results = results[:4000] + "\n\n[Results truncated]"
	}

	return results, nil
}
