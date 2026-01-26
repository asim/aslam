# Aslam - Development Guide

Personal assistant for the Aslam family. Hosted at [aslam.org](https://aslam.org).

## Architecture

```
aslam/
├── main.go           # HTTP server, routes, Anthropic integration
├── db/
│   ├── db.go         # Database functions (SQLCipher)
│   └── schema.sql    # Reference schema
├── tools/
│   ├── tools.go      # Tool definitions and execution
│   ├── web.go        # URL fetching
│   ├── wiki.go       # Wikipedia API
│   ├── islam.go      # Islamic sources API
│   └── search.go     # Web search (headless Chrome)
├── html/             # HTML templates (embedded at build)
├── scripts/
│   ├── aslam.service # Systemd service file
│   └── kb            # CLI tool for database operations
├── cmd/
│   └── aslam-cli/    # Command line client
├── .env              # Configuration (not committed)
└── ~/.aslam/
    ├── .key          # Database encryption key
    └── aslam.db      # Encrypted SQLite database
```

## Key Files

### main.go
- HTTP server on port 8000
- Google OAuth authentication
- Anthropic Claude API integration with tool use
- SSE streaming for real-time tool progress

### db/db.go
- SQLCipher encrypted database
- Sessions, conversations, messages, entries tables
- All database functions exported (GetConversation, CreateSession, etc.)

### tools/
- `tools.go` - Tool registry, definitions for Claude API
- `search.go` - Web search using Brave Search API
- `wiki.go` - Wikipedia API (free, no key needed)
- `islam.go` - Islamic sources search
- `web.go` - URL fetching with HTML-to-text conversion

## Deploying Changes

Templates are embedded at build time (`//go:embed`). After ANY change:

```bash
cd /home/exedev/aslam && go build -o aslam . && sudo systemctl restart aslam
```

## Environment Variables

Required in `.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://aslam.org/auth/callback
ALLOWED_EMAILS=email1@example.com,email2@example.com
```

Optional:
```
ANTHROPIC_MODEL=claude-3-haiku-20240307  # Default model
PORT=8000                                  # Server port
API_KEY=...                               # For CLI/API access
DEV_TOKEN=...                             # Dev bypass token
BRAVE_API_KEY=...                         # For web search
```

## Authentication

- Google OAuth with allowed email whitelist
- Sessions stored in DB, 30-day expiry
- Cookie set on `aslam.org` domain (covers www subdomain)
- www.aslam.org redirects to aslam.org

## Tools System

Claude can use tools defined in `tools/tools.go`. Each tool has:
- Name (e.g., "www", "wikipedia")
- Description (tells Claude when to use it)
- Input schema (JSON schema for parameters)

Tool execution flow:
1. Claude decides to use a tool
2. Backend executes tool, streams "Using X..." to frontend
3. Tool result sent back to Claude
4. Claude generates final response

## Web Search

Uses Brave Search API. Free tier: 2000 queries/month, then $5/1000.
Requires `BRAVE_API_KEY` in `.env`.

## Frontend

- Monospace font, 1024px max-width
- SSE streaming shows tool usage in real-time
- Voice input via Web Speech API (mic button)
- Timeago timestamps, auto-scroll

## Useful Commands

```bash
# View logs
sudo journalctl -u aslam -f

# Restart service
sudo systemctl restart aslam

# Query database
export ASLAM_KEY=$(cat ~/.aslam/.key)
./scripts/kb sql "SELECT * FROM conversations LIMIT 5;"

# List sessions
./scripts/kb sql "SELECT token, email, expires_at FROM sessions;"
```

## Known Issues

None currently.

## Trust Model

See README.md for full details. Summary:

- **Level 0 (current):** Assistant has own email (assistant@aslam.org), no access to user accounts
- **Level 1:** Read user's calendar (requires OAuth)
- **Level 2:** Read user's email (requires OAuth + security hardening)
- **Level 3:** Send as user, create events (requires confirmation flows + audit)

## Future

- [ ] Calendar integration (Level 1)
- [ ] Email read access (Level 2) 
- [ ] Full delegation (Level 3)
- [ ] Mobile PWA improvements
- [ ] Usage/cost tracking
- [ ] Audit logging
- [ ] Prompt injection defenses
