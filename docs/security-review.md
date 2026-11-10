# Security review — 10 November 2026

Reviewed the Go application routes, account/API-key/session boundaries, public reference readers, model tools, email processing, browser rendering, service worker, SQL usage and Go dependencies. This is a source review with regression tests, not a claim that every vulnerability is eliminated or a penetration test of production.

## Corrections

- Model identity comes from the verified conversation owner and is carried in context. No shared current-user pointer or callback is used for personal tools. Note updates bind the owner in SQL; server mailbox tools require an admin.
- Inbound email threads and queued replies must belong to the authenticated sender. Existing sender-domain authentication remains required by default.
- Browser account routes fail closed without OAuth and no longer accept legacy bypass keys or session tokens in URLs. OAuth state must match the browser cookie and is consumed atomically; Google email must be verified. Login attempts are bounded.
- Cross-origin mutation protection covers the router, including form endpoints. Account pages are no-store; note redirects no longer trust arbitrary Referer values.
- Markdown is sanitised using vendored DOMPurify. The Markdown parser is also vendored. Note/general linkification uses DOM text nodes rather than interpolating source text into HTML. Story narratives are escaped.
- URL fetching allows HTTP(S) on standard ports only, validates redirects and resolves/dials checked public addresses to block private-network access and DNS rebinding. Fetched content is no longer written into a shared unowned cache. Legacy unowned entries and cached answers are admin-only.
- The service worker caches static assets only and deletes the previous all-response cache on activation. It does not persist private pages or key-management responses.
- The Go toolchain and x/net dependency are updated to versions fixing the reachable findings from govulncheck.

## Validation and operational limits

Regression tests cover simultaneous users, foreign note edits, private recall, mailbox access, email thread ownership, auth bypasses, OAuth binding, cross-origin requests, and private fetch destinations/redirects. Existing API-key, ownership, signup, profiling and request-limit tests remain part of the test suite. DOM tests exercise script/event-handler and dangerous-link payloads through Markdown sanitisation and linkification.

Production proxy/header configuration, TLS, SMTP/IMAP credentials, deployment permissions, backups and the bundled SQLCipher C library require operational review beyond the Go dependency scanner. The application expects loopback proxies to overwrite X-Real-IP and preserve Host; the backend should not be publicly exposed. EMAIL_ALLOW_UNVERIFIED deliberately weakens email authentication and should remain unset/false. Account sessions already in browser storage remain until expiry/revocation; the cache cleanup occurs when the updated service worker activates.

Retrieved content remains untrusted. Prompt instructions are not an authorization boundary: server-side ownership and tool permissions must always enforce access. Admin email tools can act on the configured server mailbox; ordinary users cannot use them.

Validation on this change: `go test ./...`, the focused `-race` identity/auth/thread tests, and the browser security script passed. After upgrading Go to 1.26.10 and x/net to v0.62.0, `govulncheck ./...` reported zero reachable or imported-package vulnerabilities; one advisory remains in a required module whose affected code is not called. This does not cover native C dependencies or production configuration.
