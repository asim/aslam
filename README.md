# Aslam

An Islamic knowledge base for Muslims.

## What is this?

Aslam is a **knowledge base for seeking Islamic knowledge**. It connects you to authentic sources — Quran, Hadith, scholarly Q&A — and gives you a place to save reflections, notes, and references. AI works in the background to help find, organise, and connect information.

Everything is stored locally in a searchable database. You search it, you browse it, you own it.

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
   │         Knowledge Base             │
   │                                   │
   │   chats · notes · entries         │
   │   notes · reflections · references │
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

- **Islamic knowledge is scattered.** Across apps, websites, books, bookmarks, memory.
- **AI gives answers without sources.** You need to know *where* an answer comes from.
- **What you learn gets lost.** Notes, reflections, references — gone the moment you close the tab.
- **Authentic sources need to be accessible.** Quran, Hadith, scholarly rulings — searchable in one place.

## What lives in the knowledge base?

- **Islamic sources** — 4,200+ IslamQA scholarly Q&As, Quran, Hadith, Names of Allah (via reminder)
- **Chats** — questions you've asked, answers with cited sources
- **Notes** — your reflections, references, shared knowledge
- **Entries** — saved facts, fetched URLs, stored information

All of it indexed. All of it searchable from `/search`.

## Principles

1. **Authentic sources first** — Quran, Hadith, scholarly answers — not AI opinions
2. **Save, search, retrieve** — the primary actions
3. **Searchable** — if you can't find it, it doesn't exist
4. **Secure** — data encrypted at rest
5. **Simple** — easy to add, easy to retrieve
6. **Shareable** — community members can access and contribute
7. **Durable** — outlives any single service or platform

## Users

Access is managed through a users table with two roles:

- **admin** — full access including user management and system configuration
- **user** — access to chats, notes, and search

On first run, `ADMIN_EMAILS` seeds the initial admin(s). After that, admins add users from `/admin`. Anyone can sign up with email/password or Google OAuth — they get the `user` role by default.

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
ADMIN_EMAILS=your@email.com
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
4. Use `/notes` to save reflections, references, and things worth keeping
5. Go to `/admin` to manage users and service accounts

## Tools

The AI has access to these tools to help organise and retrieve:

- **search** — Search the knowledge base (chats, notes, IslamQA, cached sources)
- **reminder** — Search Islamic sources (Quran, Hadith, Names of Allah)
- **fetch** — Fetch URL content and save to the knowledge base
- **web_search** — Search the web for current information
- **wikipedia** — Look up factual information
- **note_add / note_update** — Save and update notes
- **email_check / email_send** — Check inbox and send email

## Purpose

A place to seek, save, and share Islamic knowledge.

The Quran and Hadith are the foundation. Scholarly answers provide context. Your reflections and notes build on top. Search ties it all together.

> *"When a man dies, his deeds come to an end except for three: ongoing charity, beneficial knowledge, or a righteous child who prays for him."*
> — Prophet Muhammad ﷺ (Sahih Muslim)

This is beneficial knowledge, made searchable.

---

*An Islamic knowledge base for Muslims.*
