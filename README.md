# Nasir

An AI assistant for the family.

*Nasir* is Arabic for "helper".

## What is this?

Nasir is, first and foremost, an **AI assistant**. You chat with it — over the web, over email, or via the CLI — and it helps you get things done: answering questions, researching topics, drafting emails, looking things up.

Everything you ever ask it, and everything you ever tell it to remember, is quietly captured into an encrypted, **searchable knowledge base** running in the background. Over time, that knowledge base becomes a second brain: not just a record of conversations with an AI, but the place where passwords, credentials, contacts, decisions, and important notes all live — searchable in one place.

You don't have to go back to the assistant to recover what you know. You can just search for it.

## How it works

```
   ┌──────────────────────────────────┐
   │       Ask Nasir (chat)           │
   │   - Web, email, CLI, API         │
   └──────────────┬───────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────┐
   │         AI Assistant              │
   │   Claude + tools (search, fetch,  │
   │   remember, recall, vault, …)     │
   └──────────────┬───────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────┐
   │      Knowledge Base (SQLCipher)   │
   │                                   │
   │   chats · messages · entries      │
   │   notes · URLs · vault items      │
   │   credentials · contacts · docs   │
   └──────────────┬───────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────┐
   │            Search                 │
   │   One box across everything you   │
   │   have ever said, saved, or       │
   │   stored.                         │
   └──────────────────────────────────┘
```

The assistant is the front door. The knowledge base runs silently behind it.

## Why?

- **Gmail is identity, not knowledge.** 10+ years of email is a graveyard, not a resource.
- **Shared docs are flat.** A Google Doc works for lists, but not for interconnected knowledge.
- **Memory is unreliable.** Things get forgotten. Context gets lost.
- **AI chats are ephemeral.** A great answer from ChatGPT is useless if you can't find it next week.
- **Continuity matters.** If I die tomorrow, what do people need to know?

Nasir is the fix: a helper you can talk to *and* a searchable archive of every helpful thing it, or you, ever produced.

## What lives in the knowledge base?

- **Chats** — every question you've ever asked and every answer given
- **Notes & memories** — things you told Nasir to remember
- **Fetched pages** — URLs the assistant has pulled and cached
- **Vault items** — passwords, credentials, accounts, important contacts (encrypted at rest)
- **Entries** — thoughts, projects, decisions, instructions, documents

All of it indexed. All of it searchable from `/search`.

## Principles

1. **Assistant first** — the primary action is asking Nasir a question
2. **Everything is captured** — conversations and memories flow into the knowledge base automatically
3. **Searchable** — if you can't find it, it doesn't exist
4. **Secure** — sensitive data encrypted at rest (SQLCipher / AES-256)
5. **Simple** — easy to add, easy to retrieve
6. **Shareable** — family can access what they need
7. **Durable** — outlives any single service or platform

## Installation

### Prerequisites

- Go 1.21+
- SQLCipher (`sudo apt-get install -y sqlcipher`)
- Brave Search API key (free tier: 2000 queries/month)

### Setup

```bash
# Clone
git clone git@github.com:asim/nasir.git
cd nasir

# Create encryption key
mkdir -p ~/.nasir
openssl rand -base64 32 > ~/.nasir/.key
chmod 600 ~/.nasir/.key

# Create .env file
cat > .env << EOF
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://nasir.org/auth/callback
ALLOWED_EMAILS=your@email.com
BRAVE_API_KEY=your-brave-api-key
EOF
chmod 600 .env

# Build and run
go build -o nasir .
./nasir
```

### Systemd Service

```bash
sudo cp scripts/nasir.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nasir
sudo systemctl start nasir
```

### Email Setup (Optional)

To enable the assistant's own email inbox:

1. Create a Google Workspace user (e.g., assistant@yourdomain.com)
2. Enable 2FA on that account
3. Generate an App Password (Security → App Passwords)
4. Add to `.env`:
   ```
   GMAIL_USER=assistant@yourdomain.com
   GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
   ```
5. Add to systemd service or restart

### First Run

1. Visit your domain and log in with Google
2. Start chatting from the home page — just type your question
3. Use `/search` to find anything you've ever asked or saved
4. Use `/vault` to store credentials and accounts
5. Go to `/admin` to document service accounts and add family admins

## Tools

The assistant has access to these tools:

- **fetch** — Fetch URL content and save to memory
- **recall** — Search memory/knowledge base
- **remember** — Save notes to memory
- **reminder** — Search Islamic sources (Quran, Hadith)
- **wikipedia** — Search Wikipedia for factual information
- **www** — Web search via Brave Search API
- **email_check** — Check assistant's inbox
- **email_send** — Send email from assistant's address
- **vault_add / vault_search / vault_update** — Manage vault items

Every tool call contributes to the knowledge base: fetched URLs are cached, remembered notes become searchable entries, vault writes become searchable vault items.

## Trust Model

The assistant operates on a levelled trust model. Access to personal accounts is earned over time as the system proves reliable and secure.

### Level 0: Sandbox (Current)
- Assistant has its own identity (assistant@yourdomain.com)
- Own email inbox, cannot access user accounts
- Users forward emails to assistant when they want it involved
- Safe to experiment — assistant can't touch your stuff

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

Nasir exists for two reasons:

**1. A helpful assistant today**
- An AI you can ask anything, over any channel
- Tools that actually do things — fetch, search, remember, email
- A conversation that isn't lost the moment you close the tab

**2. A second brain and digital estate**

Because every conversation and every memory lands in the knowledge base, over time Nasir becomes the map of your digital life — and, when the time comes, the map that your family can follow.

We live in a purely digital world. When someone dies, their family must navigate:
- Multiple email accounts
- Cryptocurrency wallets and keys
- Subscriptions and services
- Documents scattered across cloud storage
- Passwords and credentials
- Digital assets with real value

This system aims to be that map. Not just a list of accounts, but the knowledge of how to access them, what matters, what can be ignored, and what needs to be done.

> *"When a man dies, his deeds come to an end except for three: ongoing charity, beneficial knowledge, or a righteous child who prays for him."*
> — Prophet Muhammad ﷺ (Sahih Muslim)

This is the knowledge left behind.

---

*A helper, a second brain, a family vault, a digital estate.*
