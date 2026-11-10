package tools

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
)

func TestFetchRejectsPrivateDestinations(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1", "http://[::1]", "http://169.254.169.254", "http://10.0.0.1", "http://100.100.100.200", "http://[::ffff:127.0.0.1]", "file:///etc/passwd", "http://user:pass@example.com", "http://example.com:8080"} {
		u, _ := url.Parse(raw)
		if validateFetchURL(u) == nil {
			t.Fatal("allowed", raw)
		}
	}
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1"} {
		if publicAddress(netip.MustParseAddr(s)) {
			t.Fatal("allowed", s)
		}
	}
	if !publicAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address blocked")
	}
	client := publicHTTPClient()
	transport := client.Transport.(*http.Transport)
	if conn, err := transport.DialContext(context.Background(), "tcp", "localhost:80"); err == nil {
		conn.Close()
		t.Fatal("DNS private address allowed")
	}
	u, _ := url.Parse("http://127.0.0.1")
	if client.CheckRedirect(&http.Request{URL: u}, nil) == nil {
		t.Fatal("private redirect allowed")
	}
}
