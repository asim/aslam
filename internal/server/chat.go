package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"aslam/db"
)

// Accepted questions survive a browser disconnect so the saved answer can be
// recovered by /api/chat/latest. Retain the original server deadline and values.
func chatGenerationContext(request context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(chatRequestTimeout)
	if original, ok := request.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	return context.WithDeadline(context.WithoutCancel(request), deadline)
}

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

	conv, err := db.GetConversationContext(r.Context(), id)
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

	// Saved questions belong to the conversation owner, not the viewer.
	userName := "User"
	if conv.UserID != 0 {
		if owner, err := db.GetUserByIDContext(r.Context(), conv.UserID); err == nil {
			if parts := strings.Fields(owner.Name); len(parts) > 0 {
				userName = parts[0]
			}
		}
	}
	viewerName := "You"
	if session := getSession(r); session != nil {
		if parts := strings.Fields(session.Name); len(parts) > 0 {
			viewerName = parts[0]
		}
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	renderTemplate(w, r, "chat.html", map[string]interface{}{
		"Conversation": conv,
		"Messages":     messages,
		"UserName":     userName,
		"ViewerName":   viewerName,
		"IsOwner":      isOwner || isAdmin,
		"CanSend":      isOwner,
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

	if len(userMessage) > 8<<10 {
		http.Error(w, "Message exceeds 8 KiB", http.StatusRequestEntityTooLarge)
		return
	}

	// Only the owner may append questions, including when the chat is public.
	if !canSendChatMessage(w, r, convID) {
		return
	}

	// Save user message
	if err := db.AddMessage(convID, "user", userMessage); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Get conversation history for context
	messages, _ := db.GetMessages(convID)

	// Generate AI response
	ctx, cancel := chatGenerationContext(r.Context())
	defer cancel()
	response, toolsUsed, err := generateResponseWithProgressContext(ctx, messages, convID, nil)
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
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	convID, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if convID == 0 {
		jsonError(w, "Missing id", 400)
		return
	}
	if !canReadAPIChat(w, r, convID) {
		return
	}
	items, err := db.QueryAPI(r.Context(), "SELECT role,content FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 1", convID)
	if err != nil {
		jsonError(w, "Messages unavailable", 503)
		return
	}
	if len(items) == 0 {
		apiJSON(w, map[string]string{"role": "", "content": ""})
		return
	}
	apiJSON(w, items[0])
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

	if len(req.Message) > 8<<10 {
		jsonError(w, "Message exceeds 8 KiB", http.StatusRequestEntityTooLarge)
		return
	}

	// Only the owner may append questions, including when the chat is public.
	if !canSendChatMessage(w, r, req.ConversationID) {
		return
	}

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

	sendText := func(text string) {
		if r.Context().Err() == nil {
			fmt.Fprint(w, text)
			flusher.Flush()
		}
	}
	ctx, cancel := chatGenerationContext(r.Context())
	defer cancel()
	response, toolsUsed, err := generateResponseStreaming(ctx, messages, req.ConversationID, sendText)
	if err != nil {
		response = "Error: " + err.Error()
		sendText(response)
	} else {
		// Strip tool markers before saving
		response = regexp.MustCompile(`\n?!tool:\w+\n?`).ReplaceAllString(response, "")
		response = strings.TrimSpace(response)

		// Send sources footer through the stream too
		sourcesFooter := formatSourcesFooter(toolsUsed)
		if sourcesFooter != "" {
			sendText(sourcesFooter)
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

// Shared conversations are read-only, even for administrators. Without a
// per-message author ID, only the owner can add correctly attributed questions.
func canSendChatMessage(w http.ResponseWriter, r *http.Request, id int64) bool {
	conv, err := db.GetConversationContext(r.Context(), id)
	if err != nil {
		jsonError(w, "Conversation unavailable", http.StatusNotFound)
		return false
	}
	userID := getUserID(r)
	if userID == 0 || conv.UserID != userID {
		jsonError(w, "This conversation is read-only", http.StatusForbidden)
		return false
	}
	return true
}
