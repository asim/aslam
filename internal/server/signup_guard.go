package server

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type signupChallenge struct {
	answer  int
	expires time.Time
}
type signupAttempt struct {
	count   int
	expires time.Time
}
type signupProtection struct {
	sync.Mutex
	challenges map[string]signupChallenge
	attempts   map[string]signupAttempt
	total      signupAttempt
}

var signupGuard = signupProtection{challenges: make(map[string]signupChallenge), attempts: make(map[string]signupAttempt)}

func (g *signupProtection) issue() (string, string, error) {
	g.Lock()
	defer g.Unlock()
	now := time.Now()
	for id, c := range g.challenges {
		if !c.expires.After(now) {
			delete(g.challenges, id)
		}
	}
	if len(g.challenges) >= 4096 {
		return "", "", fmt.Errorf("signup busy")
	}
	id, err := newVerifyToken()
	if err != nil {
		return "", "", err
	}
	a, err := rand.Int(rand.Reader, big.NewInt(9))
	if err != nil {
		return "", "", err
	}
	b, err := rand.Int(rand.Reader, big.NewInt(9))
	if err != nil {
		return "", "", err
	}
	x, y := int(a.Int64())+1, int(b.Int64())+1
	g.challenges[id] = signupChallenge{x + y, now.Add(10 * time.Minute)}
	return id, fmt.Sprintf("What is %d + %d?", x, y), nil
}
func (g *signupProtection) check(r *http.Request) bool {
	g.Lock()
	defer g.Unlock()
	cookie, err := r.Cookie("signup_challenge")
	if err != nil {
		return false
	}
	id := r.FormValue("challenge")
	if cookie.Value != id {
		return false
	}
	c, ok := g.challenges[id]
	delete(g.challenges, id)
	answer, err := strconv.Atoi(r.FormValue("answer"))
	return ok && c.expires.After(time.Now()) && err == nil && answer == c.answer && r.FormValue("website") == ""
}
func (g *signupProtection) allow(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	// Only the local reverse proxy may supply a client address. Nginx must
	// overwrite X-Real-IP with $remote_addr, never pass a client-supplied value.
	if peer := net.ParseIP(ip); peer != nil && peer.IsLoopback() {
		if real := net.ParseIP(r.Header.Get("X-Real-IP")); real != nil {
			ip = real.String()
		}
	}
	g.Lock()
	defer g.Unlock()
	now := time.Now()
	for k, v := range g.attempts {
		if !v.expires.After(now) {
			delete(g.attempts, k)
		}
	}
	if !g.total.expires.After(now) {
		g.total = signupAttempt{expires: now.Add(time.Hour)}
	}
	if g.total.count >= 60 {
		return false
	}
	v, ok := g.attempts[ip]
	if !ok {
		if len(g.attempts) >= 4096 {
			return false
		}
		v = signupAttempt{expires: now.Add(time.Hour)}
	}
	if v.count >= 5 {
		return false
	}
	v.count++
	g.total.count++
	g.attempts[ip] = v
	return true
}
func renderSignup(w http.ResponseWriter, r *http.Request, errMsg string) {
	w.Header().Set("Cache-Control", "no-store")
	d := signupPageData(errMsg)
	if passwordSignupEnabled() {
		id, question, err := signupGuard.issue()
		if err != nil {
			http.Error(w, "Signup is busy. Please try again later.", 503)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "signup_challenge", Value: id, Path: "/auth/signup", HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: 600})
		d["Challenge"] = id
		d["Question"] = question
	}
	tmpl.ExecuteTemplate(w, "signup.html", d)
}

func sameOriginAdminPost(r *http.Request) bool {
	return r.Method == http.MethodPost && (r.Header.Get("Origin") == "https://"+r.Host || (!isHTTPS(r) && r.Header.Get("Origin") == "http://"+r.Host)) && r.Header.Get("Sec-Fetch-Site") != "cross-site" && !strings.ContainsAny(r.Host, "\r\n")
}
