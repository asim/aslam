package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"aslam/db"
)

func handleToggleNotePublic(w http.ResponseWriter, r *http.Request) {
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
	ownerID := db.GetNoteOwner(req.ID)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdminContext(r.Context(), session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
		jsonError(w, "Access denied", 403)
		return
	}
	db.AdoptOrphanNote(req.ID, userID)

	if err := db.ToggleNotePublic(req.ID, req.Public); err != nil {
		jsonError(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleNotes(w http.ResponseWriter, r *http.Request) {
	userID := getUserID(r)
	showAll := r.URL.Query().Get("show") == "all"
	items, err := db.GetNoteItems(userID, !showAll, isAdminReq(r))
	if err != nil {
		http.Error(w, "Failed to get note items", http.StatusInternalServerError)
		return
	}

	renderTemplate(w, r, "notes.html", map[string]interface{}{
		"Items":         items,
		"CurrentUserID": userID,
		"ShowAll":       showAll,
	})
}

func handleNoteView(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/notes/")
	if strings.Contains(idStr, "/") || idStr == "" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		http.NotFound(w, r)
		return
	}
	item, err := db.GetNoteItem(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	userID := getUserID(r)
	isAdmin := isAdminReq(r)
	isOwner := userID != 0 && item.UserID == userID
	// Access: owner, public, or admin. Orphaned notes (UserID == 0) are admin-only.
	if !isOwner && !item.Public && !isAdmin {
		http.NotFound(w, r)
		return
	}

	renderTemplate(w, r, "notes_view.html", map[string]interface{}{
		"Item":    item,
		"IsOwner": isOwner || isAdmin,
	})
}

func handleNoteAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		title = strings.TrimSpace(r.FormValue("name"))
	}
	content := strings.TrimSpace(r.FormValue("content"))
	if content == "" {
		content = strings.TrimSpace(r.FormValue("details"))
	}

	if title == "" {
		http.Redirect(w, r, "/notes?error=Title+required", http.StatusSeeOther)
		return
	}

	userID := getUserID(r)
	_, err := db.AddNoteItem(title, content, userID)
	if err != nil {
		http.Redirect(w, r, "/notes?error=Failed+to+add+item", http.StatusSeeOther)
		return
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/notes"
	}
	http.Redirect(w, r, referer, http.StatusSeeOther)
}

func handleNoteEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/notes/edit/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	userID := getUserID(r)
	ownerID := db.GetNoteOwner(id)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdminContext(r.Context(), session.Email)
	}
	// Orphans (ownerID == 0) are only writable by admins; an admin edit adopts the note.
	isOwner := userID != 0 && ownerID == userID

	if r.Method == "POST" {
		if !isOwner && !isAdmin {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		title := strings.TrimSpace(r.FormValue("title"))
		content := strings.TrimSpace(r.FormValue("content"))

		db.AdoptOrphanNote(id, userID)
		err := db.UpdateNoteItem(id, title, content)
		if err != nil {
			http.Redirect(w, r, "/notes?error=Failed+to+update", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	item, err := db.GetNoteItem(id)
	if err != nil {
		http.Redirect(w, r, "/notes?error=Item+not+found", http.StatusSeeOther)
		return
	}

	// Check access: owner, public, legacy, or admin
	if !isOwner && !item.Public && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	data := map[string]interface{}{
		"Item":    item,
		"IsOwner": isOwner || isAdmin,
	}
	renderTemplate(w, r, "notes_edit.html", data)
}

func handleNoteDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/notes/delete/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id == 0 {
		http.Redirect(w, r, "/notes", http.StatusSeeOther)
		return
	}

	// Verify ownership: owner or admin. Orphans are admin-only.
	userID := getUserID(r)
	ownerID := db.GetNoteOwner(id)
	isAdmin := false
	if session := getSession(r); session != nil {
		isAdmin = db.IsAdminContext(r.Context(), session.Email)
	}
	isOwner := userID != 0 && ownerID == userID
	if !isOwner && !isAdmin {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	db.DeleteNoteItem(id)
	http.Redirect(w, r, "/notes?msg=Item+deleted", http.StatusSeeOther)
}
