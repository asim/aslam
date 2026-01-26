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
- **email_check** - Check assistant's inbox (assistant@aslam.org)
- **email_send** - Send email from assistant's address

## Trust Model

The assistant operates on a levelled trust model. Access to personal accounts is earned over time as the system proves reliable and secure.

### Level 0: Sandbox (Current)
- Assistant has its own identity (assistant@aslam.org)
- Own email inbox, cannot access user accounts
- Users forward emails to assistant when they want it involved
- Safe to experiment - assistant can't touch your stuff

### Level 1: Read Calendar (Future)
- Assistant can read your Google Calendar (read-only)
- Can answer "What's on my schedule today?"
- Cannot create, modify, or delete events
- Requires: OAuth consent with calendar.readonly scope

### Level 2: Read Email (Future)
- Assistant can read your Gmail inbox
- Can summarise emails, find information, track threads
- Cannot send, delete, or modify emails
- Requires: OAuth consent with gmail.readonly scope
- Requires: Prompt injection defenses, audit logging

### Level 3: Act As You (Future)
- Assistant can send emails as you
- Can create calendar events
- Full delegation of digital identity
- Requires: Explicit confirmation flows ("Send this email? Y/N")
- Requires: Rate limits, scope limits, comprehensive audit trail
- Requires: Battle-tested prompt injection defenses

### Security Requirements (Before Advancing)
- [ ] Input sanitisation and validation
- [ ] Output validation (assistant can't leak data)
- [ ] Audit logging (every action logged with context)
- [ ] Confirmation flows for destructive actions
- [ ] Rate limiting
- [ ] Scope limiting (e.g., only last 7 days of email)
- [ ] Regular security review

## Purpose

This exists for two reasons:

**1. A second brain while alive**
- Searchable, organised knowledge
- Things that would otherwise be forgotten
- Decisions documented, context preserved

**2. A digital estate when gone**

We live in a purely digital world. When someone dies, their family must navigate:
- Multiple email accounts
- Cryptocurrency wallets and keys
- Subscriptions and services
- Documents scattered across cloud storage
- Passwords and credentials
- Digital assets with real value

This system aims to be the map. Not just a list of accounts, but the knowledge of how to access them, what matters, what can be ignored, and what needs to be done.

> *"When a man dies, his deeds come to an end except for three: ongoing charity, beneficial knowledge, or a righteous child who prays for him."*
> — Prophet Muhammad ﷺ (Sahih Muslim)

This is the knowledge left behind.

---

*A second brain, a family vault, a digital estate.*
