package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"aslam/db"
)

func handleChat(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	showAll := r.URL.Query().Get("show") == "all"
	convs, _ := db.GetRecentConversations(50, userID, !showAll, isAdminReq(r))
	renderTemplate(w, r, "chat_list.html", map[string]interface{}{
		"Conversations": convs,
		"CurrentUserID": userID,
		"ShowAll":       showAll,
	})
}

func handleChatView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/chat/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	conv, err := db.GetConversation(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	userID := getUserID(r)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdminContext(r.Context(), session.Email)
	}

	// Access check: owner, public, or admin. Orphaned chats (user_id IS NULL)
	// are admin-only until they get adopted by an update.
	isOwner := userID != 0 && conv.UserID == userID
	if !isOwner && !conv.Public && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	messages, _ := db.GetMessages(id)

	// Get user's first name from session
	userName := "You"
	if session := getSession(r); session != nil {
		parts := strings.Fields(session.Name)
		if len(parts) > 0 {
			userName = parts[0]
		}
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	renderTemplate(w, r, "chat.html", map[string]interface{}{
		"Conversation": conv,
		"Messages":     messages,
		"UserName":     userName,
		"IsOwner":      isOwner || isAdmin,
	})
}

func handleNewChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	userID := getUserID(r)

	// Optional page context: the "Chat" button on content pages posts a title
	// and the content being read, so the conversation opens pre-loaded with
	// whatever the user was looking at as context.
	title := strings.TrimSpace(r.FormValue("title"))
	pageContext := strings.TrimSpace(r.FormValue("context"))

	convTitle := "New conversation"
	if title != "" {
		convTitle = truncateRunes(title, 50)
	}

	id, err := db.CreateConversation(convTitle, userID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if pageContext != "" {
		// Stored as a "system" message: it passes the role CHECK constraint
		// (unlike "context") and buildAPIMessages folds it into the system
		// prompt, so the conversation still opens with a real user turn.
		db.AddMessage(id, "system", pageContext)
	}

	http.Redirect(w, r, fmt.Sprintf("/chat/%d", id), http.StatusSeeOther)
}

// truncateRunes shortens a string to at most n runes, appending an ellipsis if
// it was cut. Rune-safe so multi-byte titles (e.g. Arabic) aren't split.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func handleSendMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	convID, _ := strconv.ParseInt(r.FormValue("conversation_id"), 10, 64)
	userMessage := strings.TrimSpace(r.FormValue("message"))

	if convID == 0 || userMessage == "" {
		http.Error(w, "Missing fields", 400)
		return
	}

	// Set user context
	session := getSession(r)
	if session != nil {
		currentUserContext = &UserContext{Email: session.Email, Name: session.Name, ConversationID: convID}
	}

	db.AdoptOrphanConversation(convID, getUserID(r))

	// Save user message
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Get conversation history for context
	messages, _ := db.GetMessages(convID)

	// Generate AI response
	response, toolsUsed, err := generateResponseWithProgressContext(r.Context(), messages, convID, nil)
	if err != nil {
		// Save error as assistant message
		db.AddMessage(convID, "assistant", "Error: "+err.Error())
	} else {
		// Append sources if tools were used
		fullResponse := formatResponseWithSources(response, toolsUsed)
		db.AddMessage(convID, "assistant", fullResponse)
	}

	// Update conversation title if first message
	if len(messages) <= 1 {
		title := userMessage
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		db.UpdateConversationTitle(convID, title)
	}

	http.Redirect(w, r, fmt.Sprintf("/chat/%d", convID), http.StatusSeeOther)
}

func handleAPIChatLatest(w http.ResponseWriter, r *http.Request) {
	convID, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if convID == 0 {
		jsonError(w, "Missing id", 400)
		return
	}
	messages, _ := db.GetMessages(convID)
	if len(messages) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"role": "", "content": ""})
		return
	}
	last := messages[len(messages)-1]
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"role":    last.Role,
		"content": last.Content,
	})
}

func handleAPISendMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ConversationID int64  `json:"conversation_id"`
		Message        string `json:"message"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	if req.ConversationID == 0 || req.Message == "" {
		jsonError(w, "Missing fields", 400)
		return
	}

	// Set user context
	session := getSession(r)
	if session != nil {
		currentUserContext = &UserContext{Email: session.Email, Name: session.Name, ConversationID: req.ConversationID}
	}

	db.AdoptOrphanConversation(req.ConversationID, getUserID(r))

	// Save user message
	if err := db.AddMessage(req.ConversationID, "user", req.Message); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	messages, _ := db.GetMessages(req.ConversationID)

	// Update conversation title if first message
	if len(messages) <= 1 {
		title := req.Message
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		db.UpdateConversationTitle(req.ConversationID, title)
	}

	// Stream response as chunked HTTP
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "Streaming not supported", 500)
		return
	}

	response, toolsUsed, err := generateResponseStreaming(r.Context(), messages, req.ConversationID, func(text string) {
		fmt.Fprint(w, text)
		flusher.Flush()
	})
	if err != nil {
		response = "Error: " + err.Error()
		fmt.Fprint(w, response)
		flusher.Flush()
	} else {
		// Strip tool markers before saving
		response = regexp.MustCompile(`\n?!tool:\w+\n?`).ReplaceAllString(response, "")
		response = strings.TrimSpace(response)

		// Send sources footer through the stream too
		sourcesFooter := formatSourcesFooter(toolsUsed)
		if sourcesFooter != "" {
			fmt.Fprint(w, sourcesFooter)
			flusher.Flush()
		}
		response = response + sourcesFooter
	}
	db.AddMessage(req.ConversationID, "assistant", response)
}

func handleAPINewChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	userID := getUserID(r)
	id, err := db.CreateConversation("New conversation", userID)
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{"id": id})
}

func handleAPIDeleteChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	// Verify ownership: owner or admin. Orphans (ownerID == 0) are admin-only.
	userID := getUserID(r)
	ownerID := db.GetConversationOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdminContext(r.Context(), session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
		jsonError(w, "Access denied", 403)
		return
	}

	// Delete conversation (messages deleted by cascade)
	if err := db.DeleteConversation(req.ID); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleAPIChats(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	convs, err := db.GetRecentConversations(50, userID, true, isAdminReq(r))
	if err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	type convJSON struct {
		ID        int64  `json:"id"`
		Title     string `json:"title"`
		UpdatedAt string `json:"updated_at"`
	}

	var result []convJSON
	for _, c := range convs {
		result = append(result, convJSON{
			ID:        c.ID,
			Title:     c.Title,
			UpdatedAt: c.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"conversations": result})
}

func handleToggleChatPublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}

	var req struct {
		ID     int64 `json:"id"`
		Public bool  `json:"public"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}

	// Verify ownership; orphans are admin-only and get adopted on toggle.
	userID := getUserID(r)
	ownerID := db.GetConversationOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdminContext(r.Context(), session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
		jsonError(w, "Access denied", 403)
		return
	}
	db.AdoptOrphanConversation(req.ID, userID)

	if err := db.ToggleConversationPublic(req.ID, req.Public); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
