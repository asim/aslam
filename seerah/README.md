# Seerah: The Sealed Nectar

Source: user-supplied `English_ArRaheeq_AlMakhtum_THE_SEALED_NECTAR.pdf`, also linked at https://www.muslim-library.com/dl/books/English_ArRaheeq_AlMakhtum_THE_SEALED_NECTAR.pdf.

The file credits Safiur Rahman al-Mubarakpuri, translator Issam Diab, and Dar-us-Salam. No explicit republication licence was located in the supplied PDF. This provenance note does not grant permission; resolve republication rights before public deployment/distribution.

The compressed JSON contains PDF pages 8–323 (316 reading pages), 57 PDF chapter bookmarks and 232 headings detected from the source typography. Pages 1–7 are the contents listing, replaced by the navigable index; page 324 is a PDF software advertisement. These exclusions are not missing biography pages. The PDF page position is canonical: physical PDF page 30 has an erroneous printed footer of 29.

## Reproduce extraction

With Python and PyMuPDF installed, run from the repository root:

```sh
python scripts/extract_seerah.py /path/to/English_ArRaheeq_AlMakhtum_THE_SEALED_NECTAR.pdf seerah/data.json.gz seerah/question-mark-review.md
```

The JSON records the source SHA-256. Extraction removes margin headers/page labels and joins wrapped text within PDF blocks. The initial import matched every non-whitespace body character against the PDF’s extracted text; that check did not detect errors already visible in the PDF.

Reviewed source corrections: damaged `All?` (213 occurrences) becomes `Allah`, and `Qur’?` (35 occurrences) becomes `Qur’an`. The one `Muhsin?` in the quoted passage on page 10 becomes `Muhsinûn`, verified against printed page 18 of the [archive scan](https://archive.org/details/TheSealedNectar-Alhamdulillah-library.blogspot.in.pdf), superseding the earlier inferred Muhsinin. The accompanying split forms `All? u Akbar` and `Qur’? ic` become `Allahu Akbar` and `Qur’anic`. Spaces between these corrected names and punctuation or possessive endings are removed. Ordinary word separators are retained. These specific corrections happen during extraction; other question marks, correct spellings, reference numbers, page numbers and block IDs are preserved. This pass addresses the audited question-mark corruption; it is not a complete spelling or factual review.

[Question-mark review](question-mark-review.md) lists all 476 original occurrences in page/block/character order, with full original passages and decisions: 296 fixed, no unresolved flagged occurrences, and 180 logical questions retained. Each newly verified replacement records its printed scan page. The optional third extraction argument reproduces the report. This is an audit of question marks, not a complete spelling or factual review.

Correction regression tests: `python -m unittest discover -s scripts -p test_extract_seerah.py`. Dataset and indexing tests: `go test ./seerah ./db -run 'Seerah|Dataset|Reviewed'`.

## Reader and search

- `/seerah`: chapters and sections, plus the existing account's Continue Reading link.
- `/seerah/page/44`: a stable PDF-page URL, with previous/next pages, chapter links and a page jump.
- `/seerah/page/44?section=block-1#block-1`: section-specific navigation. Validated headings are stored in reading progress, including their anchor.
- Reading progress uses the existing `seerah` source key, one last location per signed-in user. Anonymous reading does not create account history, matching other sources.
- The global search, public search API and assistant's existing search tool receive page-linked Seerah results through `db.SearchAll`.
- The SQLite FTS index uses Unicode tokenization and a content hash; rebuilds are atomic. Reader data is immutable after loading. Page URLs do not depend on text hashes.

Tests cover dataset completeness, chapter/page anchors, retained citations, search, repeated indexing, per-user progress, reader boundaries and invalid section targets.

Additional scan-verified corrections: `Muzaiqb?#146;` → `Muzaiqbâ’` in the named lineage (printed scan page 16), and the five corrupted question marks following Moses → `عليه السلام` (printed scan page 72). The honorific crosses two original extraction blocks; both block IDs are retained. The archive is a verification source only; the reader keeps its original PDF pagination. The remaining 41 corrupt occurrences are now verified and corrected using the literal mapping and printed-page references in `scripts/seerah_verified.py`. This includes all three `Taim?#146;` occurrences → `Taimâ’`, prayer terms, chapter names, and attached broken entity/markup fragments. Genuine questions and other text are retained.
