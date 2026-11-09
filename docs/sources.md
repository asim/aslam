# Sources and reader pages

| Source | Records | Description |
|--------|---------|-------------|
| **Quran** | 6,348 verses | Arabic, English translation, word-by-word breakdown, commentary |
| **Hadith** | 7,265 narrations | Sahih al-Bukhari with Arabic and English |
| **Riyad us-Salihin** | 1,896 hadiths | Gardens of the Righteous (Imam An-Nawawi) — 20 books including the Book of Miscellany |
| **Names of Allah** | 99 names | Arabic, English, meaning, description, and summary |
| **IslamQA** | 4,200+ Q&As | Scholarly answers across faith, fiqh, family, history |
| **Ghazali** | 1,437 sections | Ihya Ulum al-Din (Revival of the Islamic Sciences) — 4 volumes, 37 chapters |
| **Adhkar** | 97 duas/dhikr | Morning, evening, after salah, daily, and selected supplications |
| **Arabic** | 21,000+ words | Quranic vocabulary — Arabic, transliteration, English, frequency |
| **Stories** | 25 prophets | Stories of the Prophets told through Quran verses — narrative prose with citations |
| **Tafsir Ibn Kathir** | 1,902 passages | English commentary mapped to 6,236 verses; see [provenance](tafsir.md) |
| **Seerah** | 316 reading pages | The Sealed Nectar, with chapter navigation; see [provenance](seerah.md) |
| **Reminder** | Hourly feed | Verse, hadith, name of Allah + message from reminder.dev |

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
| `/islamqa/{slug}` | IslamQA question + answer with prev/next |
| `/ghazali` | Ghazali index by volume/chapter |
| `/ghazali/{slug}` | Ghazali section with prev/next |
| `/adhkar` | Adhkar index by category |
| `/adhkar/{slug}` | Adhkar detail — Arabic, transliteration, translation, benefits |
| `/salihin` | Riyad us-Salihin index by book |
| `/salihin/{number}` | Hadith detail with prev/next (1-1896) |
| `/arabic` | Arabic vocabulary — search and paginated vocabulary |
| `/arabic/{id}` | Word detail — Arabic, transliteration, meaning, frequency |
| `/quran` | Quran index — 114 chapters |
| `/quran/{ch}` | Chapter verses |
| `/quran/{ch}/{v}` | Quran verse — Arabic + English + commentary |
| `/hadith` | Sahih al-Bukhari index by book |
| `/hadith/book/{n}` | Hadiths in a Bukhari book |
| `/hadith/{number}` | Hadith — narrator, English, Arabic |
| `/names` | 99 Names of Allah |
| `/stories` | Stories of the Prophets |
| `/stories/{slug}` | Prophet story — narrative with Quran verse citations |
| `/names/{number}` | Name of Allah — Arabic, meaning, description |
| `/profile` | User profile and picture |
| `/admin` | User management and system configuration |
| `/arabic/roots` and `/arabic/roots/{code}` | Root families and related words |
| `/arabic/reading` and `/arabic/reading/{chapter}/{verse}` | Arabic passages |
| `/seerah` and `/seerah/page/{page}` | Seerah chapters and pages |
| `/tafsir` and `/tafsir/ibn-kathir/{chapter}/{verse}` | English Ibn Kathir commentary |
| `/profile/api-keys` | Create and revoke account API keys |

## Stable URLs

Content URLs are designed to survive reloads of unchanged source content:

- **Canonical numbers** where the source provides one — `/quran/2/255`, `/hadith/1`, `/salihin/1`, `/names/1`
- **Content slugs** for everything else — `/islamqa/can-babies-see-the-angels-7a3fbc`, `/adhkar/supplication-before-sleeping-9e21b3`, `/ghazali/v1-chapter-i-knowledge-p1-b3f8a2`

Slugs are `slugify(title) + "-" + sha1(canonical-content)[:6]`, computed at load time. The same source content always produces the same URL, so reloading the same content preserves links. Changes to canonical source content can change a slug; check saved-link compatibility when correcting datasets.

## Embedded Datasets

| File | Contents |
|------|----------|
| `data/islamqa.zip` | 4,200+ IslamQA scholarly Q&As |
| `data/ghazali.zip` | 1,437 sections of Ihya Ulum al-Din |
| `data/adhkar.zip` | 97 duas and dhikr |
| `data/salihin.zip` | 1,896 Riyad us-Salihin hadiths |
| `data/arabic.zip` | 21,000+ Quranic Arabic vocabulary |
| `data/sources.zip` | Quran (6,348), Hadith (7,265), Names of Allah (99) |
| `data/tafsir.zip` | English Tafsir Ibn Kathir; see [import details](tafsir.md) |
| `data/prophets.json` | Stories of the Prophets |
| `data/quran_chapters.json` | Chapter names, meanings and verse counts |
| `data/seerah.zip` | The Sealed Nectar, preserving 316 reading pages and chapter bookmarks |

Reference data is embedded at build time. Most collections are imported into SQLite and full-text indexes; Seerah also keeps a book representation in memory. Follow the specific loader's version or archive-hash check when updating data. Do not assume every collection uses the same reload mechanism.

## Quran chapter metadata

`data/quran_chapters.json` contains the 114 chapter names, Arabic names, English meanings and verse counts from https://api.quran.com/api/v4/chapters?language=en (retrieved 2026-10-25). The chapter index decodes this metadata once; reading progress remains specific to the signed-in user.

See also [Arabic learning](arabic-learning.md), [Seerah](seerah.md) and [Tafsir](tafsir.md) for source-specific behavior and provenance.
