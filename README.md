# Aslam

A personal assistant for the Aslam family. Hosted at [aslam.org](https://aslam.org).

## What is this?

This is a centralised repository of knowledge, thoughts, and information for Asim Aslam and family. It exists to solve a simple problem: life accumulates information across too many places—email, docs, notes, browser bookmarks, memory—and none of it is searchable, organised, or transferable.

## Why?

- **Gmail is identity, not knowledge.** 10+ years of email is a graveyard, not a resource.
- **Shared docs are flat.** A Google Doc works for lists, but not for interconnected knowledge.
- **Memory is unreliable.** Things get forgotten. Context gets lost.
- **Continuity matters.** If I die tomorrow, what do people need to know?

## What goes here?

- **Thoughts & ideas** — things worth remembering, half-formed or complete
- **Projects** — what I'm working on, why, and where things stand
- **Assets & accounts** — passwords, credentials, important accounts (encrypted)
- **Contacts & relationships** — people, context, history
- **Documents** — important files, records, references
- **Decisions** — why certain choices were made
- **Instructions** — how to do things that only I know how to do

## Principles

1. **Searchable** — if you can't find it, it doesn't exist
2. **Structured** — tagged, categorised, linked
3. **Secure** — sensitive data encrypted at rest
4. **Simple** — easy to add, easy to retrieve
5. **Shareable** — family can access what they need
6. **Durable** — outlives any single service or platform

## Installation

### Prerequisites

- Go 1.21+
- SQLCipher (`sudo apt-get install -y sqlcipher`)
- Brave Search API key (free tier: 2000 queries/month)

### Setup

```bash
# Clone
git clone git@github.com:asim/aslam.git
cd aslam

# Create encryption key
mkdir -p ~/.aslam
openssl rand -base64 32 > ~/.aslam/.key
chmod 600 ~/.aslam/.key

# Create .env file
cat > .env << EOF
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://aslam.org/auth/callback
ALLOWED_EMAILS=your@email.com
BRAVE_API_KEY=your-brave-api-key
EOF
chmod 600 .env

# Build and run
go build -o aslam .
./aslam
```

### Systemd Service

```bash
sudo cp scripts/aslam.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aslam
sudo systemctl start aslam
```

## Tools

The assistant has access to these tools:

- **fetch** - Fetch URL content and save to memory
- **recall** - Search memory/knowledge base
- **remember** - Save notes to memory
- **reminder** - Search Islamic sources (Quran, Hadith)
- **wikipedia** - Search Wikipedia for factual information
- **www** - Web search via Brave Search API

---

*A second brain, a family vault, a digital estate.*
