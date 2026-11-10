# Architecture

Aslam is a Go application for browsing Islamic reference material, searching it, and keeping personal chats and notes. Reference retrieval does not call a model. Questions use a shared Anthropic response loop with tools; web, HTTP API and queued email work share conversation ownership and model limits.

## Runtime

[main.go](../main.go) calls [server.Run](../internal/server/server.go). Startup loads configuration, opens the encrypted database, runs migrations, loads/indexes Seerah and imports Tafsir. Other versioned reference datasets load in a background goroutine. The server parses embedded templates once, registers routes and starts task, email and daily-content workers.

The first startup or a dataset version change can involve substantial import work. Reader requests query stored data rather than decoding source archives. Seerah pages use the in-memory book; its search index is in SQLite.

## Requests and rendering

Host validation and request admission wrap the HTTP router. Public reader pages use optional authentication; account pages enforce authentication and ownership. HTTP integration endpoints accept account keys or sessions according to their route; MCP requires an account key. See [API and MCP](api.md).

Templates and assets are embedded from `internal/server/html/`. Presentation belongs in `app.css`, with reusable classes and scoped page rules. Browser behavior lives in `app.js` and page scripts. CSS, JavaScript and template changes require rebuilding the binary. Versioned static assets support immutable caching; unversioned assets support revalidation.

Browser session lookups are reused only within one request. A new request rechecks the database; API-key identity takes precedence over a browser session. SQL connections do not carry user identities.

## Storage and search

SQLCipher stores accounts, sessions, chats, notes, reading progress, reference records and full-text indexes. The database defaults to `~/.aslam/aslam.db`; the encryption key comes from `ASLAM_KEY` or `~/.aslam/.key`.

The pool permits four open connections and retains up to four idle connections without a timed idle expiry. This avoids repeating SQLCipher key derivation while bounding connection caches. User authorization and ownership are checked by application queries, independently of which connection is used.

`db/db.go` owns the main migrations and persistence helpers. Additional files cover API keys, signup review, model budgets, source imports and ordered page indexes. Request-aware queries use contexts and bounded results. Keep long source text out of index keys and use transactions for atomic changes.

Published-reference search is separate from account-aware search. The knowledge API and MCP retrieval tools must not return private chats, notes or cached model answers. Source wording, Arabic, translations and scholarly commentary remain distinct.

## Model and channel flow

1. Authenticate the requester and identify the conversation owner.
2. Check access and persist the user message.
3. Run the shared model/tool loop with the conversation context and usage reservation.
4. Persist the response and deliver it through the originating channel.

Chat streams text to the browser/API; it is not an SSE protocol. Email threads map Message-ID/References to conversations through `email_threads`. Background tasks use the same ownership and usage checks. New channels should adapt this flow rather than introduce a second model path; each channel still needs its own authorization and delivery tests.

Model tools are registered in `internal/tools/` and wired to persistence by the server's storage adapters. Chat and MCP share the knowledge API handlers for `collections`, `search`, `contents`, `browse` and `read`, including full passages, attribution and pagination. Chat keeps personal recall in `search_saved` and uses the reference tools for cited summaries. MCP remains retrieval-only and does not expose model execution or personal account actions.

## Accounts and trust

Email/password registration creates a pending request, then requires email verification and admin approval before account creation. Google OAuth is a separate signup/login path. `db.IsUser` checks verified membership; `db.UserExists` only checks whether an account exists.

Account API keys are stored as hashes and inherit account permissions. Keys cannot mint other keys: key management uses a browser session. Inbound assistant email requires a verified sender account and authenticated sender-domain headers. See [operations](operations.md) for email setup and model limits.

## Repository layout

| Path | Responsibility |
| --- | --- |
| `main.go` | Server entry point |
| `internal/server/` | Routes, handlers, rendering, model calls and workers |
| `internal/server/html/` | Embedded templates, shared stylesheet and browser assets |
| `internal/discovery/` | API catalog, OpenAPI and agent guide |
| `internal/tools/` | Model tool definitions and external integrations |
| `internal/seerah/` | Seerah archive reader and page navigation |
| `db/` | SQLCipher persistence, migrations, indexes and quotas |
| `data/` | Embedded reference datasets and metadata |
| `scripts/` | Deployment, database administration and source extraction |
| `cmd/` | CLI and standalone tax utilities |
| `docs/` | Architecture, setup, operations and source provenance |

For operational constraints and diagnostics, see [request limits](request-limits.md) and [memory profiling](memory-profiling.md).
