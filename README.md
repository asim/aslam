# Aslam

A knowledge base for the family.

## What is this?

Aslam is a **family knowledge base**. You save notes, credentials, thoughts, and information — and it's all encrypted, searchable, and organised in one place. AI works in the background to help organise, connect to sources, and retrieve what you need.

Everything is stored in an encrypted database (SQLCipher / AES-256). You search it, you browse it, you own it.

## How it works

```
   ┌──────────────────────────────────┐
   │           Input                   │
   │   - Web, email, CLI, API         │
   └──────────────┬───────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────┐
   │         AI (background)           │
   │   Organises, fetches, connects    │
   │   to sources (Quran, Hadith, web) │
   └──────────────┬───────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────┐
   │      Knowledge Base (SQLCipher)   │
   │                                   │
   │   chats · notes · entries         │
   │   credentials · contacts · docs   │
   └──────────────┬───────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────┐
   │            Search                 │
   │   One box across everything you   │
   │   have ever saved or stored.      │
   └──────────────────────────────────┘
```

## Why?

- **Gmail is identity, not knowledge.** 10+ years of email is a graveyard, not a resource.
- **Shared docs are flat.** A Google Doc works for lists, but not for interconnected knowledge.
- **Memory is unreliable.** Things get forgotten. Context gets lost.
- **Continuity matters.** If I die tomorrow, what do people need to know?

## What lives in the knowledge base?

- **Chats** — interactions with the tool, stored and searchable
- **Notes** — credentials, accounts, contacts, instructions, documents, anything worth keeping
- **Entries** — thoughts, memories, fetched URLs, saved references

All of it indexed. All of it searchable from `/search`.

## Principles

1. **Save, search, retrieve** — the primary actions
2. **Everything is captured** — notes, chats and entries flow into the knowledge base
3. **Searchable** — if you can't find it, it doesn't exist
4. **Secure** — all data encrypted at rest (SQLCipher / AES-256)
5. **Simple** — easy to add, easy to retrieve
6. **Shareable** — family members can access what they need
7. **Durable** — outlives any single service or platform

## Users

Access is managed through a users table with two roles:

- **admin** — full access including user management and system configuration
- **user** — access to chats, notes, and search

On first run, `ALLOWED_EMAILS` seeds the initial admin(s). After that, admins add users from `/admin`.

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
sudo cp scripts/aslam.service /etc/systemd/system/aslam.service
sudo systemctl daemon-reload
sudo systemctl enable aslam
sudo systemctl start aslam
```

### Auto-deploy

A deploy script checks GitHub for changes, rebuilds, and restarts:

```bash
# Add to cron (every 5 minutes)
(crontab -l 2>/dev/null; echo "*/5 * * * * /home/aslam/scripts/deploy.sh >> /home/aslam/deploy.log 2>&1") | crontab -
```

### First Run

1. Visit your domain and log in with Google
2. Use the home page input to interact with the tool
3. Use `/search` to find anything you've saved
4. Use `/notes` to store credentials, accounts, and important info
5. Go to `/admin` to manage users and service accounts

## Tools

The AI has access to these tools to help organise and retrieve:

- **fetch** — Fetch URL content and save to the knowledge base
- **recall** — Search the knowledge base
- **remember** — Save a note or fact
- **reminder** — Search Islamic sources (Quran, Hadith)
- **wikipedia** — Look up factual information
- **www** — Web search via Brave Search API
- **email_check** — Check the inbox
- **email_send** — Send email
- **note_add / note_search / note_update** — Manage notes (credentials, accounts, contacts, docs)

## Purpose

Aslam exists for two reasons:

**1. A family knowledge base today**
- A single place for everything worth keeping
- Credentials, contacts, decisions, instructions — searchable and encrypted
- Islamic knowledge sources built in

**2. A digital estate when needed**

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

*A family knowledge base.*
