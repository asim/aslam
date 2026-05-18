# Aslam

An Islamic knowledge base for Muslims.

## What is this?

Aslam is a **knowledge base for seeking Islamic knowledge**. It connects you to authentic sources — Quran, Hadith, scholarly Q&A, classical works, and daily adhkar — and gives you a place to save notes, reflections, and references. AI works in the background to help find, organise, and connect information.

Everything is stored locally in an encrypted, searchable database. You search it, you browse it, you own it.

## Islamic Sources

| Source | Records | Description |
|--------|---------|-------------|
| **Quran** | 6,348 verses | Full text with Arabic, English translation, and commentary |
| **Hadith** | 7,265 narrations | Sahih al-Bukhari with Arabic and English |
| **Names of Allah** | 99 names | Arabic, meaning, description, and summary |
| **IslamQA** | 4,200+ Q&As | Scholarly answers across faith, fiqh, family, history |
| **Ghazali** | 1,437 sections | Ihya Ulum al-Din (Revival of the Islamic Sciences) |
| **Adhkar** | 97 duas/dhikr | Morning, evening, after salah, daily, and selected |
| **Reminder** | Hourly feed | Verse, hadith, name of Allah + reflection from reminder.dev |

~19,500 indexed records of Islamic knowledge, all searchable from one box.

## Features

- **Search** — one box across Quran, Hadith, Names, IslamQA, Ghazali, Adhkar, chats, and notes
- **Prayer times** — calculated locally using Moonsighting Committee method, auto-detected location
- **Daily reminder** — hourly verse, hadith, and name of Allah from reminder.dev
- **Question of the day** — random IslamQA question on the home page
- **Chats** — ask questions, AI searches authentic sources for answers
- **Notes** — save reflections, references, bookmarks from any content page
- **Public/private** — content is private by default, share with a toggle
- **Browse** — index pages for IslamQA (by category), Ghazali (by volume/chapter), Adhkar (by category)
- **Save anything** — every content page has a Save button that creates a note with a link back
- **PWA** — installable on mobile/desktop, pull-to-refresh
- **User accounts** — email/password or Google OAuth, admin/user roles
- **Auto-deploy** — cron checks GitHub every 5 minutes, rebuilds on changes

## Pages

| Route | What it does |
|-------|-------------|
| `/` | Public landing page |
| `/home` | Home — ask questions, prayer times, daily reminder, question of the day |
| `/search` | Search across all sources and user content |
| `/chat` | Chat list (Mine / All) |
| `/chat/{id}` | Chat view with public/private toggle and delete |
| `/notes` | Notes list (Mine / All) with inline create |
| `/notes/{id}` | Note view with source links |
| `/notes/edit/{id}` | Edit note |
| `/islamqa` | IslamQA index by category |
| `/islamqa/{id}` | IslamQA question + answer with prev/next |
| `/ghazali` | Ghazali index by volume/chapter |
| `/ghazali/{id}` | Ghazali section with prev/next |
| `/adhkar` | Adhkar index by category |
| `/adhkar/{id}` | Adhkar detail — Arabic, transliteration, translation, benefits |
| `/quran/{ch}/{v}` | Quran verse — Arabic + English + commentary |
| `/hadith/{id}` | Hadith — narrator, English, Arabic |
| `/name/{id}` | Name of Allah — Arabic, meaning, description |
| `/profile` | User profile and picture |
| `/admin` | User management and system configuration |

## AI Tools

The AI has access to these tools during chat:

- **search** — Search the knowledge base (user-scoped: own + public content)
- **reminder** — Search Quran, Hadith, Names of Allah via the reminder API
- **islamqa** — Search IslamQA scholarly answers
- **ghazali** — Search Ghazali's Ihya Ulum al-Din
- **fetch** — Fetch URL content and save to the knowledge base
- **web_search** — Search the web for current information
- **wikipedia** — Look up factual information
- **note_add / note_update** — Save and update notes

## Users

Access is managed through a users table with two roles:

- **admin** — full access including user management and system configuration
- **user** — access to chats, notes, and search

On first run, `ADMIN_EMAILS` seeds the initial admin(s). Anyone can sign up with email/password or Google OAuth — they get the `user` role by default. Content is private by default; users can toggle individual chats and notes to public.

## Installation

### Prerequisites

- Go 1.21+
- SQLCipher (`sudo apt-get install -y sqlcipher`)

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

1. Visit your domain and sign up or log in
2. The home page shows prayer times, daily reminder, and a question box
3. Browse `/islamqa`, `/ghazali`, `/adhkar` for Islamic sources
4. Use `/search` to find anything across all sources
5. Use `/notes` to save reflections and bookmarks
6. Go to `/admin` to manage users and configuration

## Embedded Datasets

| File | Contents |
|------|----------|
| `islamqa.zip` | 4,200+ IslamQA scholarly Q&As |
| `ghazali.zip` | 1,437 sections of Ihya Ulum al-Din |
| `adhkar.zip` | 97 duas and dhikr |
| `sources.zip` | Quran (6,348 verses), Hadith (7,265), Names of Allah (99) |

All datasets are embedded in the binary at build time and loaded into SQLite with FTS indexing on first run. Versioned — bump the version constant to force a reload when data changes.

## Purpose

A place to seek, save, and share Islamic knowledge.

The Quran and Hadith are the foundation. Scholarly answers provide context. Classical works deepen understanding. Daily adhkar ground the practice. Your notes and reflections build on top. Search ties it all together.

> *"When a man dies, his deeds come to an end except for three: ongoing charity, beneficial knowledge, or a righteous child who prays for him."*
> — Prophet Muhammad ﷺ (Sahih Muslim)

This is beneficial knowledge, made searchable.

---

*An Islamic knowledge base for Muslims.*
