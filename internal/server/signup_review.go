package server

import (
	"aslam/db"
	"aslam/internal/tools"
	"log"
	"net/http"
)

func handleReviewSignup(w http.ResponseWriter, r *http.Request) {
	if !sameOriginAdminPost(r) {
		http.Error(w, "Invalid request origin", 403)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", 400)
		return
	}
	action := r.FormValue("action")
	if action != "approve" && action != "reject" {
		http.Error(w, "Invalid action", 400)
		return
	}
	if err := db.ReviewSignup(r.Context(), r.FormValue("email"), r.FormValue("token"), action == "approve"); err != nil {
		http.Redirect(w, r, "/admin?error=Request+could+not+be+updated.+Refresh+and+try+again.#signup-requests", 303)
		return
	}
	if action == "approve" {
		if _, err := tools.SendEmail(r.FormValue("email"), "Your Aslam account is approved", "Your account has been approved. You can now log in with your email and password:\n\n"+baseURL()+"/auth/login"); err != nil {
			log.Printf("Approval notification failed: %v", err)
			http.Redirect(w, r, "/admin?error=Account+approved,+but+notification+email+failed.#signup-requests", 303)
			return
		}
	}
	http.Redirect(w, r, "/admin?msg=Signup+request+updated#signup-requests", 303)
}
