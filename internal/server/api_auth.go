package server

import (
	"aslam/db"
	"context"
	"net/http"
	"strconv"
	"strings"
)

type apiSessionKey struct{}

// Keys establish an account identity; they are not a bypass of ownership checks.
func accountAPI(next http.Handler, keyOnly bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var session *db.Session
		auth := r.Header.Get("Authorization")
		if auth != "" {
			parts := strings.Fields(auth)
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && len(parts[1]) == 70 {
				var err error
				session, err = db.APIKeySession(r.Context(), parts[1])
				if err != nil {
					session = nil
				}
			}
		} else if !keyOnly {
			session = getSession(r)
			if session != nil && !db.IsUserContext(r.Context(), session.Email) {
				session = nil
			}
		}
		if session == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="aslam"`)
			jsonError(w, "A valid account API key or session is required", 401)
			return
		}
		http.NewCrossOriginProtection().Handler(next).ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiSessionKey{}, session)))
	})
}
func handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	// Key management is browser-session-only: an existing key cannot mint keys.
	session := getSession(r)
	if session == nil || !db.IsUserContext(r.Context(), session.Email) {
		http.Redirect(w, r, "/auth/login", 303)
		return
	}
	id := db.GetUserIDContext(r.Context(), session.Email)
	w.Header().Set("Cache-Control", "no-store")
	var token, errText string
	if r.Method == "POST" {
		if !sameOriginAdminPost(r) {
			http.Error(w, "Forbidden", 403)
			return
		}
		if r.FormValue("action") == "revoke" {
			keyID, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
			if err != nil {
				http.Error(w, "Invalid key", 400)
				return
			}
			if err = db.RevokeAPIKey(r.Context(), id, keyID); err != nil {
				http.Error(w, "Unable to revoke key", 500)
				return
			}
			http.Redirect(w, r, "/profile/api-keys", 303)
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if name == "" || len(name) > 80 {
			errText = "Enter a name of up to 80 bytes."
		} else {
			var err error
			token, err = db.CreateAPIKey(r.Context(), id, name)
			if err != nil {
				errText = "Unable to create key. You can have up to 20 keys."
			}
		}
	} else if r.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	keys, err := db.ListAPIKeys(r.Context(), id)
	if err != nil {
		http.Error(w, "Unable to load keys", 500)
		return
	}
	renderTemplate(w, r, "api_keys.html", map[string]interface{}{"Keys": keys, "Token": token, "Error": errText})
}
