package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"aslam/db"
	"aslam/internal/tools"

	"golang.org/x/crypto/bcrypt"
)

// optionalAuth wraps handlers that are readable without an account. It keeps
// the www redirect that requireAuth performs, but never forces a login: the
// handler renders for signed-in and anonymous visitors alike. Use it for source
// content (Quran, Hadith, IslamQA…), which is public knowledge and worth having
// shareable and indexable. Anything holding user data, or that spends API
// credits, stays behind requireAuth.
func optionalAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "www.aslam.org" {
			http.Redirect(w, r, "https://aslam.org"+r.URL.Path, http.StatusMovedPermanently)
			return
		}
		handler(w, r)
	}
}

// isLoggedIn reports whether the request carries a session for a valid user.
func isLoggedIn(r *http.Request) bool {
	session := getSession(r)
	return session != nil && db.IsUserContext(r.Context(), session.Email)
}

func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Redirect www to non-www
		if r.Host == "www.aslam.org" {
			http.Redirect(w, r, "https://aslam.org"+r.URL.Path, http.StatusMovedPermanently)
			return
		}

		// Check if auth is configured
		if googleClientID == "" {
			// No auth configured, allow all
			handler(w, r)
			return
		}

		// Check API key (header)
		if apiKey != "" && r.Header.Get("X-API-Key") == apiKey {
			handler(w, r)
			return
		}

		// Check dev token (query param or header)
		if devToken != "" {
			if r.URL.Query().Get("dev") == devToken || r.Header.Get("X-Dev-Token") == devToken {
				handler(w, r)
				return
			}
		}

		// Accept session token from URL (OAuth redirect into PWA)
		if authToken := r.URL.Query().Get("auth"); authToken != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    authToken,
				Path:     "/",
				Domain:   "aslam.org",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   30 * 24 * 60 * 60,
				Expires:  time.Now().Add(30 * 24 * time.Hour),
			})
			http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
			return
		}

		session := getSession(r)
		if session == nil {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		if !db.IsUserContext(r.Context(), session.Email) {
			http.Error(w, "Unauthorized: your email is not allowed", http.StatusForbidden)
			return
		}
		handler(w, r)
	}
}

func getSession(r *http.Request) *db.Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	return db.GetSessionByTokenContext(r.Context(), cookie.Value)
}

func createSession(email, name string) string {
	token, err := db.CreateSession(email, name)
	if err != nil {
		log.Printf("Failed to create session: %v", err)
		return ""
	}
	return token
}

func isHTTPS(r *http.Request) bool {
	// Check X-Forwarded-Proto for reverse proxy setups
	if proto := r.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return true
	}
	return r.TLS != nil
}

func startGoogleOAuth(w http.ResponseWriter, r *http.Request) {
	if googleClientID == "" {
		http.Error(w, "OAuth not configured", 500)
		return
	}

	// Generate state for CSRF protection
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	// Store state in database (persists across restarts)
	db.CreateOAuthState(state)

	// Store state in cookie (works across www/non-www with Domain)
	http.SetCookie(w, &http.Cookie{
		Name:  "oauth_state",
		Value: state,
		Path:  "/",

		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   300, // 5 minutes
	})

	// Redirect to Google OAuth
	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email%%20profile&state=%s",
		url.QueryEscape(googleClientID),
		url.QueryEscape(googleRedirectURI),
		url.QueryEscape(state),
	)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	// If ?google=true, trigger Google OAuth flow
	if r.URL.Query().Get("google") == "true" {
		startGoogleOAuth(w, r)
		return
	}

	if r.Method == "POST" {
		handleLoginPost(w, r)
		return
	}

	// GET: show login page
	errMsg := r.URL.Query().Get("error")
	tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
		"Error":         errMsg,
		"GoogleEnabled": googleClientID != "",
	})
}

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")

	if email == "" || password == "" {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "Email and password are required",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	user, err := db.GetUserByEmailContext(r.Context(), email)
	if err != nil || user.PasswordHash == "" {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "Invalid email or password",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "Invalid email or password",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	// Correct password, but the address was never confirmed. Checked after the
	// password so this does not reveal which addresses are registered.
	if !db.IsVerifiedContext(r.Context(), email) {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "Please confirm your email address first — check your inbox for the link we sent.",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	// Create session
	token := createSession(email, user.Name)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Domain:   "aslam.org",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
		Expires:  time.Now().Add(30 * 24 * time.Hour),
	})

	log.Printf("User logged in via password: %s (%s)", user.Name, email)
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func handlePrivacy(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, r, "privacy.html", nil)
}

// passwordSignupEnabled reports whether self-service email/password
// registration is open.
//
// It is closed by default. The form has no email verification, CAPTCHA or rate
// limit, so anyone can script it to mint accounts against addresses they do not
// own — and because db.IsUser doubles as the allowlist for the email channel,
// each one becomes an authorised sender to the assistant. Google OAuth is the
// supported way in: it proves the address and is costly to abuse in bulk.
//
// Existing password accounts can still log in; only registration is closed.
// If Google OAuth is not configured there would be no way to register at all,
// so it stays open in that case.
//
// Otherwise it is gated on being able to send a confirmation email: with
// verification in place an account is useless until its address is proven, so
// registration is open when SMTP is configured. Without SMTP there is no way to
// prove an address, so it stays shut rather than reopening the original hole.
// ALLOW_PASSWORD_SIGNUP=false forces it off regardless.
func passwordSignupEnabled() bool {
	if googleClientID == "" {
		return true
	}
	if v := os.Getenv("ALLOW_PASSWORD_SIGNUP"); v != "" {
		return strings.EqualFold(v, "true")
	}
	return canSendEmail()
}

// canSendEmail reports whether outbound mail is configured.
func canSendEmail() bool {
	return os.Getenv("GMAIL_USER") != "" && os.Getenv("GMAIL_APP_PASSWORD") != ""
}

// signupPageData is the template data for signup.html.
func signupPageData(errMsg string) map[string]interface{} {
	return map[string]interface{}{
		"Error":          errMsg,
		"GoogleEnabled":  googleClientID != "",
		"PasswordSignup": passwordSignupEnabled(),
	}
}

// verifyTokenTTL is how long a verification link stays useful, and
// verifyResendInterval is the minimum gap between verification emails to one
// address — without it, signup and resend become a way to flood an inbox.
const (
	verifyResendInterval = 2 * time.Minute
	pendingSignupTTL     = 24 * time.Hour
)

// newVerifyToken returns a crypto-random, URL-safe token.
func newVerifyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sendVerificationEmail mails a confirmation link to a newly registered address.
func sendVerificationEmail(email, name, token string) error {
	link := fmt.Sprintf("%s/auth/verify?token=%s", baseURL(), url.QueryEscape(token))
	greeting := "Assalamu alaikum"
	if name != "" {
		greeting = "Assalamu alaikum " + name
	}
	body := fmt.Sprintf(`%s,

Confirm your email address to finish setting up your Aslam account:

%s

If you didn't sign up for Aslam, you can ignore this email — the account
stays inactive and no one can use it.

— Aslam
`, greeting, link)

	_, err := tools.SendEmail(email, "Confirm your email for Aslam", body)
	return err
}

// baseURL is the public origin used to build links in outbound email.
func baseURL() string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("BASE_URL")), "/"); v != "" {
		return v
	}
	// Derived from the OAuth redirect so links match the deployment without
	// extra configuration.
	if googleRedirectURI != "" {
		if u, err := url.Parse(googleRedirectURI); err == nil && u.Scheme != "" && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return "https://aslam.org"
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		handleSignupPost(w, r)
		return
	}

	// GET: show signup page
	tmpl.ExecuteTemplate(w, "signup.html", signupPageData(r.URL.Query().Get("error")))
}

func handleSignupPost(w http.ResponseWriter, r *http.Request) {
	if !passwordSignupEnabled() {
		log.Printf("Rejected password signup attempt for %s (registration is Google-only)",
			strings.TrimSpace(strings.ToLower(r.FormValue("email"))))
		tmpl.ExecuteTemplate(w, "signup.html", signupPageData("Please sign up with Google."))
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	password := r.FormValue("password")

	// Validation
	if email == "" || !strings.Contains(email, "@") || !strings.Contains(email[strings.Index(email, "@"):], ".") {
		tmpl.ExecuteTemplate(w, "signup.html", signupPageData("Please enter a valid email address"))
		return
	}
	if len(password) < 8 {
		tmpl.ExecuteTemplate(w, "signup.html", signupPageData("Password must be at least 8 characters"))
		return
	}

	token, err := newVerifyToken()
	if err != nil {
		log.Printf("Failed to generate verification token: %v", err)
		tmpl.ExecuteTemplate(w, "signup.html", signupPageData("Something went wrong. Please try again."))
		return
	}

	// Real accounts are never overwritten by a registration attempt. Pending
	// submissions live separately and are handled below.
	if db.UserExists(email) {
		tmpl.ExecuteTemplate(w, "signup.html", signupPageData("An account with this email already exists"))
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		tmpl.ExecuteTemplate(w, "signup.html", signupPageData("Something went wrong. Please try again."))
		return
	}

	// Keep the submission outside the users table until the address is proven.
	// Repeated attempts for the same address are rate-limited in the database.
	if err := db.SavePendingSignup(email, name, string(hash), token, verifyResendInterval, pendingSignupTTL); err != nil {
		if errors.Is(err, db.ErrVerificationRecentlySent) {
			log.Printf("Not resending verification to %s: %v", email, err)
			renderVerifySent(w, email)
		} else {
			log.Printf("Failed to save pending signup for %s: %v", email, err)
			tmpl.ExecuteTemplate(w, "signup.html", signupPageData("Could not create account. Please try again."))
		}
		return
	}

	if err := sendVerificationEmail(email, name, token); err != nil {
		db.DeletePendingSignup(email)
		log.Printf("Failed to send verification email to %s: %v", email, err)
		tmpl.ExecuteTemplate(w, "signup.html", signupPageData("We couldn't send the confirmation email. Please try again shortly."))
		return
	}

	log.Printf("New user signed up (pending verification): %s (%s)", name, email)
	renderVerifySent(w, email)
}

func renderVerifySent(w http.ResponseWriter, email string) {
	tmpl.ExecuteTemplate(w, "verify_sent.html", map[string]interface{}{"Email": email})
}

// handleVerify consumes a verification link and signs the account in.
func handleVerify(w http.ResponseWriter, r *http.Request) {
	email, err := db.VerifyUserByToken(r.URL.Query().Get("token"))
	if err != nil {
		tmpl.ExecuteTemplate(w, "login.html", map[string]interface{}{
			"Error":         "That confirmation link is invalid or has already been used. Try logging in, or sign up again.",
			"GoogleEnabled": googleClientID != "",
		})
		return
	}

	name := ""
	if u, err := db.GetUserByEmailContext(r.Context(), email); err == nil {
		name = u.Name
	}

	token := createSession(email, name)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Domain:   "aslam.org",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
		Expires:  time.Now().Add(30 * 24 * time.Hour),
	})

	log.Printf("Email verified, user activated: %s (%s)", name, email)
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	queryState := r.URL.Query().Get("state")

	// Verify state exists in database (survives restarts)
	if !db.ValidateOAuthState(queryState) {
		log.Printf("OAuth callback: state not found in db: %s", queryState)
		http.Error(w, "Invalid or expired state. Try logging in again.", 400)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name: "oauth_state",
		Path: "/",

		MaxAge: -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code provided", 400)
		return
	}

	// Exchange code for token
	tokenResp, err := http.PostForm("https://oauth2.googleapis.com/token", url.Values{
		"client_id":     {googleClientID},
		"client_secret": {googleClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {googleRedirectURI},
	})
	if err != nil {
		http.Error(w, "Token exchange failed", 500)
		return
	}
	defer tokenResp.Body.Close()

	var tokenData struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenData); err != nil {
		http.Error(w, "Failed to parse token", 500)
		return
	}

	// Get user info
	userReq, _ := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	userReq.Header.Set("Authorization", "Bearer "+tokenData.AccessToken)
	userResp, err := http.DefaultClient.Do(userReq)
	if err != nil {
		http.Error(w, "Failed to get user info", 500)
		return
	}
	defer userResp.Body.Close()

	var userInfo struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to parse user info", 500)
		return
	}

	email := strings.ToLower(userInfo.Email)

	// Auto-create user if they don't exist (open registration via Google)
	if !db.IsUserContext(r.Context(), email) {
		if err := db.AddUser(email, userInfo.Name, "user", "google"); err != nil {
			log.Printf("Failed to auto-create user %s: %v", email, err)
			http.Error(w, "Failed to create account", 500)
			return
		}
		log.Printf("Auto-created user via Google OAuth: %s (%s)", userInfo.Name, email)
	}

	// Update name and picture from Google on every login
	if userInfo.Name != "" || userInfo.Picture != "" {
		db.UpdateUserProfile(email, userInfo.Name, userInfo.Picture)
	}

	// Create session
	token := createSession(email, userInfo.Name)
	log.Printf("Created session token: %s... (len=%d)", token[:min(10, len(token))], len(token))
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Domain:   "aslam.org",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 60 * 60,
		Expires:  time.Now().Add(30 * 24 * time.Hour),
	})

	log.Printf("User logged in: %s (%s)", userInfo.Name, email)
	http.Redirect(w, r, "/home?auth="+url.QueryEscape(token), http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		db.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Path:   "/",
		Domain: "aslam.org",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getUserID returns the database user ID from the request session, or 0 if unauthenticated.
func getUserID(r *http.Request) int64 {
	session := getSession(r)
	if session == nil {
		return 0
	}
	return db.GetUserIDContext(r.Context(), session.Email)
}

func isAdminReq(r *http.Request) bool {
	session := getSession(r)
	if session == nil {
		return false
	}
	return db.IsAdminContext(r.Context(), session.Email)
}

// requireAdmin wraps handlers that need admin access
func requireAdmin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getSession(r)
		if session == nil {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}

		// Check if user is admin
		if !db.IsAdminContext(r.Context(), session.Email) {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}

		handler(w, r)
	}
}
