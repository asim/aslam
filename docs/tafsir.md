# English Tafsir Ibn Kathir

Source: QUL / Tarteel, https://qul.tarteel.ai/resources/tafsir/35

The supplied `en-tafisr-ibn-kathir.json.zip` is retained unchanged as
`data/tafsir.zip`. SHA-256:
`562788b8ed1cc14d00802fdc0e5aa6edf1e6f90da2b33839b75d654a12fe6297`.
It maps all 6,236 Quran verses to 1,902 commentary passages; 4,334 entries
reference shared passages. Attribution does not establish a reuse licence:
QUL's resource-specific licence tab says it does not have copyright information
for this resource. No translator, publisher, or licence is inferred.

To validate and replace a downloaded archive:

```sh
go run ./scripts/tafsir -input /path/to/en-tafisr-ibn-kathir.json.zip
```

Startup imports each archive version once, transactionally, into SQLite and its
FTS index. JSON is decoded passage by passage; page requests read only the
requested passage or a bounded listing. The original wording is preserved.
Display HTML permits basic formatting and Arabic direction, removing executable
markup, external embeds, links and arbitrary attributes. Plain text is indexed.
Invalid coverage, references, or empty passages abort the import without replacing
the previous dataset.

`/tafsir` lists chapters; `/tafsir/ibn-kathir/{chapter}` lists passages;
`/tafsir/ibn-kathir/{chapter}/{verse}` opens the commentary. Shared verses redirect
to their canonical passage. Signed-in readers resume that passage through the
existing reading-progress system. Save stores its link; Chat supplies an explicitly
labelled, bounded excerpt. Commentary is separate from Quran translations.

The `tafsir` collection uses existing search, collections, contents, browse and
resource APIs, and the corresponding MCP tools. Browse's `group` is the chapter
number. Resource reads accept the reader path and return plaintext, safe HTML,
covered ayahs, attribution, and adjacent passage links. Existing API-key rules
apply; public search stays public. Reading and indexing do not invoke models.
