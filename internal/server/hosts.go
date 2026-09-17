package server

import (
	"net"
	"net/http"
	"strings"
)

// Validate the original Host before authentication or database work. Proxies
// must preserve Host rather than replacing an unknown domain with aslam.org.
func restrictHosts(next http.Handler, configured string) http.Handler {
	if strings.TrimSpace(configured) == "" {
		configured = "aslam.org,www.aslam.org,localhost,127.0.0.1,::1"
	}
	allowed := make(map[string]bool)
	for _, host := range strings.Split(configured, ",") {
		host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
		if host != "" {
			allowed[host] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if !allowed[host] {
			http.Error(w, "Unrecognized host", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
