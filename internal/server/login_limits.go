package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var loginAttempts = struct {
	sync.Mutex
	values map[string]signupAttempt
}{values: map[string]signupAttempt{}}

func allowLoginAttempt(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	if peer := net.ParseIP(ip); peer != nil && peer.IsLoopback() {
		if real := net.ParseIP(r.Header.Get("X-Real-IP")); real != nil {
			ip = real.String()
		}
	}
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	now := time.Now()
	for k, v := range loginAttempts.values {
		if !v.expires.After(now) {
			delete(loginAttempts.values, k)
		}
	}
	keys := []string{"ip:" + ip, "email:" + strings.ToLower(strings.TrimSpace(r.FormValue("email")))}
	if len(loginAttempts.values) > 4096 {
		return false
	}
	for _, key := range keys {
		if loginAttempts.values[key].count >= 10 {
			return false
		}
	}
	for _, key := range keys {
		v := loginAttempts.values[key]
		if v.count == 0 {
			v.expires = now.Add(time.Minute)
		}
		v.count++
		loginAttempts.values[key] = v
	}
	return true
}
