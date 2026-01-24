# Aslam - Development Guide

Personal knowledge base and assistant for the Aslam family.

## Overview

This is a conversational knowledge base with Islamic values baked into the system prompt. It stores conversations and entries in an encrypted SQLite database (SQLCipher, AES-256).

## Architecture

```
aslam/
├── main.go           # HTTP server, routes, Anthropic integration
├── schema.sql        # Database schema (entries, conversations, messages)
├── kb                # CLI tool for database operations
├── templates/        # HTML templates (terminal-style UI)
├── .env              # Configuration (ANTHROPIC_API_KEY) - not committed
└── ~/.aslam/
    ├── .key          # Database encryption key
    └── aslam.db      # Encrypted SQLite database
```

## Running

```bash
# Set API key
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Run server
./aslam
# Serves on http://localhost:8000
```

## Key Design Decisions

1. **Islamic Values in System Prompt**: All AI responses are framed within Sharia principles:
   - No riba (interest-based finance)
   - No maysir (speculation/gambling)
   - No haram activities or consumption
   - Family values aligned with Islamic ethics
   - Tool framing: not a replacement for dua, scholars, or Allah

2. **Encryption at Rest**: Database is encrypted with SQLCipher. Key stored in `~/.aslam/.key`.

3. **Terminal Aesthetic**: Black background, white text, monospace font. Simple and functional.

4. **No Auth Yet**: Currently no authentication. Future: Google OAuth or magic link.

## CLI Usage

```bash
export ASLAM_KEY=$(cat ~/.aslam/.key)

./kb add thought "Title" "Content"
./kb add credential "Service" "username/password" '{"url":"..."}'
./kb search "query"
./kb list [type]
./kb get <id>
```

## Entry Types

- `thought` - Ideas, reflections
- `project` - Things being worked on
- `credential` - Passwords, accounts (encrypted at rest)
- `contact` - People, relationships
- `document` - Important files, records
- `decision` - Why choices were made
- `instruction` - How to do things
- `note` - General notes

## Future Enhancements

- [ ] Authentication (Google OAuth / magic link)
- [ ] Email integration (Gmail API)
- [ ] Calendar integration
- [ ] Conversation summarization
- [ ] Auto-tagging with AI
- [ ] Mobile app / PWA
- [ ] Backup/export functionality
- [ ] Multi-user family access
