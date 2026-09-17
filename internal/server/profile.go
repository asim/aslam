package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"aslam/db"
)

func handleUpdateLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", 405)
		return
	}
	session := getSession(r)
	if session == nil {
		jsonError(w, "Unauthorized", 401)
		return
	}
	var req struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		Timezone  string  `json:"timezone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request", 400)
		return
	}
	if req.Latitude == 0 && req.Longitude == 0 {
		jsonError(w, "Invalid coordinates", 400)
		return
	}
	db.UpdateUserLocation(session.Email, req.Latitude, req.Longitude, req.Timezone)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
		return
	}

	user, err := db.GetUserByEmailContext(r.Context(), session.Email)
	if err != nil {
		http.Error(w, "User not found", 404)
		return
	}

	if r.Method == "POST" {
		r.ParseMultipartForm(5 << 20) // 5MB max

		name := strings.TrimSpace(r.FormValue("name"))
		if name != "" {
			user.Name = name
		}

		// Handle picture upload — resize to 128px and base64 encode
		file, header, err := r.FormFile("picture")
		if err == nil && header != nil {
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, 2<<20)) // 2MB limit
			if err == nil && len(data) > 0 {
				resized := resizeAndEncode(data)
				if resized != "" {
					user.Picture = resized
				}
			}
		}

		if latStr := r.FormValue("latitude"); latStr != "" {
			if v, err := strconv.ParseFloat(latStr, 64); err == nil {
				user.Latitude = v
			}
		}
		if lngStr := r.FormValue("longitude"); lngStr != "" {
			if v, err := strconv.ParseFloat(lngStr, 64); err == nil {
				user.Longitude = v
			}
		}
		if tz := strings.TrimSpace(r.FormValue("timezone")); tz != "" {
			user.Timezone = tz
		}

		db.UpdateUserProfile(session.Email, user.Name, user.Picture)
		db.UpdateUserLocation(session.Email, user.Latitude, user.Longitude, user.Timezone)
		http.Redirect(w, r, "/profile?msg=Profile+updated", http.StatusSeeOther)
		return
	}

	renderTemplate(w, r, "profile.html", map[string]interface{}{
		"User":    user,
		"Message": r.URL.Query().Get("msg"),
	})
}

func resizeAndEncode(data []byte) string {
	// For simplicity, store as base64 data URI without resizing.
	// Go's stdlib doesn't include image resizing; we'd need a third-party lib.
	// Instead, just cap at reasonable size and encode.
	if len(data) > 500*1024 {
		return ""
	}
	mime := http.DetectContentType(data)
	if !strings.HasPrefix(mime, "image/") {
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return "data:" + mime + ";base64," + encoded
}
