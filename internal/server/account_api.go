package server

import (
	"aslam/db"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func canReadAPIChat(w http.ResponseWriter, r *http.Request, id int64) bool {
	conv, err := db.GetConversationContext(r.Context(), id)
	if err != nil || (!conv.Public && conv.UserID != getUserID(r) && !isAdminReq(r)) {
		jsonError(w, "Chat not found", 404)
		return false
	}
	return true
}
func handleAPIChatMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		jsonError(w, "Invalid id", 400)
		return
	}
	if !canReadAPIChat(w, r, id) {
		return
	}
	offset, limit, err := apiPage(r)
	if err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	items, err := db.QueryAPI(r.Context(), "SELECT id,role,content,created_at FROM messages WHERE conversation_id=? ORDER BY id LIMIT ? OFFSET ?", id, limit+1, offset)
	apiList(w, r, items, err, offset, limit)
}
func apiList(w http.ResponseWriter, r *http.Request, items []map[string]any, err error, offset, limit int) {
	if err != nil {
		jsonError(w, "Data unavailable", 503)
		return
	}
	next := ""
	if len(items) > limit {
		items = items[:limit]
		q := r.URL.Query()
		q.Set("offset", strconv.Itoa(offset+limit))
		next = r.URL.Path + "?" + q.Encode()
	}
	apiJSON(w, map[string]any{"results": items, "next": next})
}
func handleAPINotes(w http.ResponseWriter, r *http.Request) {
	uid := getUserID(r)
	suffix := strings.TrimPrefix(r.URL.Path, "/api/notes")
	id := int64(0)
	if suffix != "" {
		var err error
		id, err = strconv.ParseInt(strings.TrimPrefix(suffix, "/"), 10, 64)
		if err != nil || id <= 0 {
			jsonError(w, "Invalid note id", 400)
			return
		}
	}
	if r.Method == "GET" {
		offset, limit, err := apiPage(r)
		if err != nil {
			jsonError(w, err.Error(), 400)
			return
		}
		items, err := db.QueryAPI(r.Context(), "SELECT id,title,content,public,created_at,updated_at FROM notes_v2 WHERE user_id=? AND (?=0 OR id=?) ORDER BY updated_at DESC,id DESC LIMIT ? OFFSET ?", uid, id, id, limit+1, offset)
		if err == nil && id != 0 {
			if len(items) == 0 {
				jsonError(w, "Note not found", 404)
			} else {
				apiJSON(w, items[0])
			}
			return
		}
		apiList(w, r, items, err, offset, limit)
		return
	}
	if r.Method == "DELETE" && id != 0 {
		result, err := db.DB.ExecContext(r.Context(), "DELETE FROM notes_v2 WHERE id=? AND user_id=?", id, uid)
		if err != nil {
			jsonError(w, "Unable to delete note", 503)
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			jsonError(w, "Note not found", 404)
			return
		}
		w.WriteHeader(204)
		return
	}
	if (r.Method != "POST" || id != 0) && (r.Method != "PUT" || id == 0) {
		jsonError(w, "Method not allowed", 405)
		return
	}
	var in struct {
		Title, Content string
		Public         bool
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || strings.TrimSpace(in.Title) == "" || len(in.Title) > 500 || len(in.Content) > 100000 {
		jsonError(w, "Provide a title (up to 500 bytes) and content (up to 100000 bytes)", 400)
		return
	}
	if id == 0 {
		result, err := db.DB.ExecContext(r.Context(), "INSERT INTO notes_v2(title,content,user_id,public) VALUES(?,?,?,?)", in.Title, in.Content, uid, in.Public)
		if err != nil {
			jsonError(w, "Unable to save note", 503)
			return
		}
		id, _ = result.LastInsertId()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
	} else {
		result, err := db.DB.ExecContext(r.Context(), "UPDATE notes_v2 SET title=?,content=?,public=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?", in.Title, in.Content, in.Public, id, uid)
		if err != nil {
			jsonError(w, "Unable to save note", 503)
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			jsonError(w, "Note not found", 404)
			return
		}
	}
	apiJSON(w, map[string]any{"id": id})
}
func handleAPIReadingProgress(w http.ResponseWriter, r *http.Request) {
	uid := getUserID(r)
	switch r.Method {
	case "GET":
		items, err := db.QueryAPI(r.Context(), "SELECT source,path,title,updated_at FROM reading_progress WHERE user_id=? ORDER BY updated_at DESC LIMIT 50", uid)
		if err != nil {
			jsonError(w, "Progress unavailable", 503)
			return
		}
		apiJSON(w, map[string]any{"results": items})
	case "POST":
		var in struct{ Source, Path, Title string }
		if json.NewDecoder(r.Body).Decode(&in) != nil || knowledgeCollections[in.Source] == "" || len(in.Path) > 1000 || len(in.Title) > 500 || !strings.HasPrefix(in.Path, "/") || strings.HasPrefix(in.Path, "//") || strings.Contains(in.Path, "\\") {
			jsonError(w, "Invalid reading progress", 400)
			return
		}
		// The browser shares one Continue reading position across vocabulary,
		// roots and passages. Collection names are aliases of that namespace.
		if in.Source == "roots" || in.Source == "reading" {
			in.Source = "arabic"
		}
		root := strings.Split(strings.TrimPrefix(in.Path, "/"), "/")[0]
		if knowledgeCollections[root] == "" || root != in.Source {
			jsonError(w, "Invalid resource path", 400)
			return
		}
		_, err := db.DB.ExecContext(r.Context(), "INSERT INTO reading_progress(user_id,source,path,title) VALUES(?,?,?,?) ON CONFLICT(user_id,source) DO UPDATE SET path=excluded.path,title=excluded.title,updated_at=CURRENT_TIMESTAMP", uid, in.Source, in.Path, in.Title)
		if err != nil {
			jsonError(w, "Unable to save progress", 503)
			return
		}
		apiJSON(w, map[string]string{"status": "ok"})
	default:
		jsonError(w, "Method not allowed", 405)
	}
}
func handleAPIProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	u, err := db.GetUserByEmailContext(r.Context(), getSession(r).Email)
	if err != nil {
		jsonError(w, "Account unavailable", 503)
		return
	}
	apiJSON(w, map[string]any{"id": getUserID(r), "email": u.Email, "name": u.Name, "role": u.Role, "latitude": u.Latitude, "longitude": u.Longitude, "timezone": u.Timezone})
}
