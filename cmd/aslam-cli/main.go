package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var baseURL = getEnv("ASLAM_URL", "http://localhost:8000")
var apiKey = os.Getenv("ASLAM_API_KEY")

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "chat":
		handleChat(args)
	case "chats":
		handleChats()
	case "search":
		handleSearch(args)
	case "new":
		handleNewChat()
	case "help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Aslam CLI - Family Assistant

Usage: aslam-cli <command> [args]

Commands:
  chat [id]          Start or continue a chat (interactive mode)
  chat [id] "msg"    Send a single message
  chats              List recent conversations
  new                Create a new conversation
  search <query>     Search conversations
  help               Show this help

Environment:
  ASLAM_API_KEY      API key for authentication
  ASLAM_URL          Base URL (default: http://localhost:8000)`)
}

func handleChat(args []string) {
	var convID int64 = 0
	var message string

	if len(args) >= 1 {
		if id, err := strconv.ParseInt(args[0], 10, 64); err == nil {
			convID = id
			if len(args) >= 2 {
				message = strings.Join(args[1:], " ")
			}
		} else {
			// First arg is message, create new chat
			message = strings.Join(args, " ")
		}
	}

	// Create new conversation if needed
	if convID == 0 {
		var err error
		convID, err = createConversation()
		if err != nil {
			fmt.Println("Error creating conversation:", err)
			os.Exit(1)
		}
		fmt.Printf("Created conversation #%d\n\n", convID)
	}

	// Single message mode
	if message != "" {
		resp, err := sendMessage(convID, message)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		fmt.Println(resp)
		return
	}

	// Interactive mode
	fmt.Printf("Chat #%d (type 'exit' to quit)\n\n", convID)
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		if input == "exit" || input == "quit" {
			break
		}

		fmt.Println("\nThinking...")
		resp, err := sendMessage(convID, input)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		fmt.Printf("\n%s\n\n", resp)
	}
}

func handleChats() {
	resp, err := doGet("/api/chats")
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	var result struct {
		Conversations []struct {
			ID        int64  `json:"id"`
			Title     string `json:"title"`
			UpdatedAt string `json:"updated_at"`
		} `json:"conversations"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		// Try to show raw response
		fmt.Println(string(resp))
		return
	}

	if len(result.Conversations) == 0 {
		fmt.Println("No conversations yet.")
		return
	}

	fmt.Println("Recent Chats:")
	fmt.Println()
	for _, c := range result.Conversations {
		title := c.Title
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		fmt.Printf("  #%d  %s\n", c.ID, title)
	}
}

func handleSearch(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: aslam-cli search <query>")
		os.Exit(1)
	}

	query := strings.Join(args, " ")
	resp, err := doGet("/api/search?q=" + query)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	var result struct {
		Results []struct {
			ConversationID int64  `json:"ConversationID"`
			Title          string `json:"Title"`
			Role           string `json:"Role"`
			Content        string `json:"Content"`
		} `json:"results"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		fmt.Println(string(resp))
		return
	}

	if len(result.Results) == 0 {
		fmt.Println("No results found.")
		return
	}

	fmt.Printf("Found %d results:\n\n", len(result.Results))
	for _, r := range result.Results {
		content := r.Content
		if len(content) > 100 {
			content = content[:100] + "..."
		}
		fmt.Printf("  [#%d] %s\n  %s: %s\n\n", r.ConversationID, r.Title, r.Role, content)
	}
}

func handleNewChat() {
	convID, err := createConversation()
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	fmt.Printf("Created conversation #%d\n", convID)
	fmt.Printf("Start chatting with: aslam-cli chat %d\n", convID)
}

func createConversation() (int64, error) {
	resp, err := doPost("/api/chat/new", nil)
	if err != nil {
		return 0, err
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return 0, err
	}
	return result.ID, nil
}

func sendMessage(convID int64, message string) (string, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"conversation_id": convID,
		"message":         message,
	})

	resp, err := doPost("/api/chat/send", body)
	if err != nil {
		return "", err
	}

	var result struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", err
	}

	if result.Error != "" {
		return "", fmt.Errorf(result.Error)
	}
	return result.Response, nil
}

func doGet(path string) ([]byte, error) {
	url := baseURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func doPost(path string, body []byte) ([]byte, error) {
	url := baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
