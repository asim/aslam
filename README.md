# Aslam

An Islamic knowledge base for Muslims.

## What is this?

Aslam is a **knowledge base for seeking Islamic knowledge**. It connects you to authentic sources — Quran, Hadith, scholarly Q&A, classical works, daily adhkar, and Quranic Arabic vocabulary. Save notes, share reflections, and build a searchable library of everything you learn.

AI works in the background to help find, organise, and connect information across sources — but the sources themselves are authentic, cited, and browsable.

## Islamic Sources

| Source | Records | Description |
|--------|---------|-------------|
| **Quran** | 6,348 verses | Arabic, English translation, word-by-word breakdown, commentary |
| **Hadith** | 7,265 narrations | Sahih al-Bukhari with Arabic and English |
| **Riyad us-Salihin** | 1,217 hadiths | Gardens of the Righteous (Imam An-Nawawi) — 19 books on manners, virtues, knowledge |
| **Names of Allah** | 99 names | Arabic, English, meaning, description, and summary |
| **IslamQA** | 4,200+ Q&As | Scholarly answers across faith, fiqh, family, history |
| **Ghazali** | 1,437 sections | Ihya Ulum al-Din (Revival of the Islamic Sciences) — 4 volumes, 37 chapters |
| **Adhkar** | 97 duas/dhikr | Morning, evening, after salah, daily, and selected supplications |
| **Arabic** | 21,000+ words | Quranic vocabulary — Arabic, transliteration, English, frequency |
| **Reminder** | Hourly feed | Verse, hadith, name of Allah + message from reminder.dev |

~41,000 indexed records of Islamic knowledge, all searchable.

## Features

- **Search** — one box across Quran, Hadith, Names, IslamQA, Ghazali, Adhkar, Riyad us-Salihin, chats, and notes
- **Prayer times** — Moonsighting Committee method, auto-detected location
- **Daily reminder** — hourly verse, hadith, name of Allah, and message
- **Question of the day** — random IslamQA question on the home page
- **Browse** — index pages for IslamQA, Ghazali, Adhkar, Riyad us-Salihin (with prev/next navigation)
- **Arabic vocabulary** — search 21,000+ Quranic words by English or Arabic, with transliteration and frequency
- **Chats** — ask questions, AI searches authentic sources with query reformulation
- **Notes** — save reflections, bookmarks from any content page
- **Save anything** — every content page has a Save button that creates a note with a link back
- **Public/private** — content is private by default, share with a toggle
- **PWA** — installable on mobile/desktop
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
| `/salihin` | Riyad us-Salihin index by book |
| `/salihin/{id}` | Hadith detail with prev/next |
| `/arabic` | Arabic vocabulary — search + top 100 most frequent words |
| `/arabic/{id}` | Word detail — Arabic, transliteration, meaning, frequency |
| `/quran/{ch}/{v}` | Quran verse — Arabic + English + commentary |
| `/hadith/{id}` | Hadith — narrator, English, Arabic |
| `/name/{id}` | Name of Allah — Arabic, meaning, description |
| `/profile` | User profile and picture |
| `/admin` | User management and system configuration |

## AI Tools

The AI has access to these tools during chat, with query reformulation for better FTS recall:

- **search** — Search all sources (user-scoped: own + public content)
- **reminder** — Quran, Hadith, Names of Allah via semantic search (reminder API)
- **islamqa** — IslamQA scholarly answers
- **ghazali** — Ghazali's Ihya Ulum al-Din
- **adhkar** — Duas and dhikr
- **salihin** — Riyad us-Salihin
- **fetch** — Fetch URL content and save to knowledge base
- **web_search** — Search the web
- **wikipedia** — Wikipedia lookup
- **note_add / note_update** — Save and update notes

## Users

- **admin** — full access including user management and system configuration
- **user** — access to chats, notes, and search

On first run, `ADMIN_EMAILS` seeds the initial admin(s). Anyone can sign up with email/password or Google OAuth — they get the `user` role by default. Content is private by default; users can toggle individual chats and notes to public.

## Installation

### Prerequisites

- Go 1.21+
- SQLCipher (`sudo apt-get install -y sqlcipher`)

### Setup

```bash
git clone git@github.com:asim/aslam.git
cd aslam

mkdir -p ~/.aslam
openssl rand -base64 32 > ~/.aslam/.key
chmod 600 ~/.aslam/.key

cat > .env << EOF
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://aslam.org/auth/callback
ADMIN_EMAILS=your@email.com
BRAVE_API_KEY=your-brave-api-key
EOF
chmod 600 .env

go build -o aslam .
./aslam
```

### Auto-deploy

```bash
sudo cp scripts/aslam.service /etc/systemd/system/aslam.service
sudo systemctl daemon-reload
sudo systemctl enable --now aslam

(crontab -l 2>/dev/null; echo "*/5 * * * * /home/aslam/scripts/deploy.sh >> /home/aslam/deploy.log 2>&1") | crontab -
```

## Embedded Datasets

| File | Contents |
|------|----------|
| `data/islamqa.zip` | 4,200+ IslamQA scholarly Q&As |
| `data/ghazali.zip` | 1,437 sections of Ihya Ulum al-Din |
| `data/adhkar.zip` | 97 duas and dhikr |
| `data/salihin.zip` | 1,217 Riyad us-Salihin hadiths |
| `data/arabic.zip` | 21,000+ Quranic Arabic vocabulary |
| `data/sources.zip` | Quran (6,348), Hadith (7,265), Names of Allah (99) |

All datasets are embedded in the binary at build time and loaded into SQLite with FTS indexing on first run. Versioned — bump the version constant to force a reload when data changes.

## Purpose

A place to seek, save, and share Islamic knowledge.

The Quran and Hadith are the foundation. Scholarly answers provide context. Classical works deepen understanding. Daily adhkar ground the practice. Arabic opens the door to the original sources. Your notes and reflections build on top. Search ties it all together.

> *"When a man dies, his deeds come to an end except for three: ongoing charity, beneficial knowledge, or a righteous child who prays for him."*
> — Prophet Muhammad ﷺ (Sahih Muslim)

This is beneficial knowledge, made searchable.

---

*An Islamic knowledge base for Muslims.*
