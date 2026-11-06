package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestSignupChallengeSingleUseAndBinding(t *testing.T) {
	g := signupProtection{challenges: map[string]signupChallenge{}, attempts: map[string]signupAttempt{}}
	id, _, err := g.issue()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://aslam.org/auth/signup", nil)
	r.Form = url.Values{"challenge": {id}, "answer": {strconv.Itoa(g.challenges[id].answer)}}
	if g.check(r) {
		t.Fatal("accepted missing cookie")
	}
	r.AddCookie(&http.Cookie{Name: "signup_challenge", Value: id})
	if !g.check(r) {
		t.Fatal("valid challenge rejected")
	}
	if g.check(r) {
		t.Fatal("challenge replay accepted")
	}
	for _, trap := range []bool{false, true} {
		id, _, _ := g.issue()
		r := httptest.NewRequest("POST", "https://aslam.org/auth/signup", nil)
		r.AddCookie(&http.Cookie{Name: "signup_challenge", Value: id})
		r.Form = url.Values{"challenge": {id}, "answer": {strconv.Itoa(g.challenges[id].answer)}}
		if trap {
			r.Form.Set("website", "bot")
		} else {
			c := g.challenges[id]
			c.expires = time.Now().Add(-time.Minute)
			g.challenges[id] = c
		}
		if g.check(r) {
			t.Fatal("accepted expired challenge or honeypot")
		}
	}
}
func TestSignupLimitsAndProxy(t *testing.T) {
	g := signupProtection{attempts: map[string]signupAttempt{}}
	r := httptest.NewRequest("POST", "https://aslam.org/auth/signup", nil)
	r.RemoteAddr = "192.0.2.1:1234"
	for i := 0; i < 5; i++ {
		if !g.allow(r) {
			t.Fatal("early limit")
		}
	}
	r.Header.Set("X-Real-IP", "192.0.2.2")
	if g.allow(r) {
		t.Fatal("spoofed header bypassed limit")
	}
	r.RemoteAddr = "127.0.0.1:1234"
	if !g.allow(r) {
		t.Fatal("local proxy address ignored")
	}
	g.total.count = 60
	if g.allow(r) {
		t.Fatal("global limit ignored")
	}
}
func TestSignupReviewOrigin(t *testing.T) {
	r := httptest.NewRequest("POST", "https://aslam.org/admin/review-signup", nil)
	r.Header.Set("Origin", "https://evil.example")
	if sameOriginAdminPost(r) {
		t.Fatal("cross-origin approval")
	}
	r.Header.Set("Origin", "https://aslam.org")
	if !sameOriginAdminPost(r) {
		t.Fatal("same-origin approval blocked")
	}
}
