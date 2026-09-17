package tools

import (
	"fmt"
	"os"
	"strings"
)

// AuthServID returns the identity our receiving mail server stamps into the
// Authentication-Results header it adds. Only a header bearing this id is
// trusted; see VerifyAuthResults.
func AuthServID() string {
	if v := strings.TrimSpace(os.Getenv("EMAIL_AUTHSERV_ID")); v != "" {
		return strings.ToLower(v)
	}
	return "mx.google.com"
}

// VerifyAuthResults reports whether an Authentication-Results header (RFC 8601)
// corroborates that a message really came from the domain its From header
// claims. A From header on its own proves nothing — it is trivially forged —
// so this is what stands between a spoofed sender and the allowlist.
//
// A DMARC pass is sufficient by itself: DMARC requires SPF or DKIM to pass and
// to be aligned with the From domain, which is exactly the property wanted.
// Many domains publish no DMARC policy though, so an explicit SPF or DKIM pass
// whose own domain aligns with the From domain is also accepted — the same
// alignment check performed by hand.
//
// The header must carry our own server's authserv-id. Without that check a
// sender could simply include a forged Authentication-Results in the message
// body and have it believed whenever our server did not add one of its own.
func VerifyAuthResults(authResults, fromAddr string) (bool, string) {
	fromDomain := domainOf(fromAddr)
	if fromDomain == "" {
		return false, "unparseable From address"
	}

	authResults = strings.TrimSpace(authResults)
	if authResults == "" {
		return false, "no Authentication-Results header"
	}

	// Parenthesised comments may contain ';' and '=', which would confuse the
	// segment split below.
	clean := strings.ToLower(stripParens(authResults))

	segments := strings.Split(clean, ";")
	if len(segments) == 0 {
		return false, "malformed Authentication-Results header"
	}

	// The first segment is the authserv-id of the server that added the
	// header. Anything else is not ours and cannot be trusted.
	if got := strings.TrimSpace(segments[0]); got != AuthServID() {
		return false, fmt.Sprintf("Authentication-Results from unexpected server %q", got)
	}

	for _, seg := range segments[1:] {
		method, result := leadingMethod(seg)
		if result != "pass" {
			continue
		}

		switch method {
		case "dmarc":
			return true, "dmarc=pass"

		case "dkim":
			d := prop(seg, "header.d")
			if d == "" {
				d = strings.TrimPrefix(prop(seg, "header.i"), "@")
			}
			if aligned(d, fromDomain) {
				return true, fmt.Sprintf("dkim=pass aligned with %s", d)
			}

		case "spf":
			m := domainOf(prop(seg, "smtp.mailfrom"))
			if aligned(m, fromDomain) {
				return true, fmt.Sprintf("spf=pass aligned with %s", m)
			}
		}
	}

	return false, "no DMARC pass and no SPF/DKIM pass aligned with " + fromDomain
}

// leadingMethod pulls "dkim", "pass" out of a segment like
// `dkim=pass header.i=@example.com header.s=s1`.
func leadingMethod(seg string) (method, result string) {
	seg = strings.TrimSpace(seg)
	eq := strings.Index(seg, "=")
	if eq < 0 {
		return "", ""
	}
	method = strings.TrimSpace(seg[:eq])
	rest := strings.TrimSpace(seg[eq+1:])
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		rest = rest[:i]
	}
	return method, rest
}

// prop reads a `key=value` property from within one segment.
func prop(seg, key string) string {
	for _, field := range strings.Fields(seg) {
		if v, ok := strings.CutPrefix(field, key+"="); ok {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

// aligned reports whether an authenticated domain covers the From domain,
// either exactly or as a parent (relaxed DMARC alignment).
func aligned(authDomain, fromDomain string) bool {
	authDomain = strings.Trim(strings.TrimSpace(authDomain), ".")
	if authDomain == "" || fromDomain == "" {
		return false
	}
	return authDomain == fromDomain || strings.HasSuffix(fromDomain, "."+authDomain)
}

// domainOf returns the lowercased domain part of an address.
func domainOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.Index(addr, "<"); i >= 0 {
		if j := strings.Index(addr, ">"); j > i {
			addr = addr[i+1 : j]
		}
	}
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return ""
	}
	return strings.ToLower(strings.Trim(strings.TrimSpace(addr[at+1:]), ".>"))
}

// stripParens removes parenthesised comments, which may contain delimiters.
func stripParens(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
				b.WriteRune(' ')
				continue
			}
			b.WriteRune(r)
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
