# Seerah: The Sealed Nectar

Source: user-supplied `English_ArRaheeq_AlMakhtum_THE_SEALED_NECTAR.pdf`, also linked at https://www.muslim-library.com/dl/books/English_ArRaheeq_AlMakhtum_THE_SEALED_NECTAR.pdf.

The file credits Safiur Rahman al-Mubarakpuri, translator Issam Diab, and Dar-us-Salam. No explicit republication licence was located in the supplied PDF. This provenance note does not grant permission; resolve republication rights before public deployment/distribution.

The compressed JSON contains PDF pages 8–323 (316 reading pages), 57 PDF chapter bookmarks and 232 headings detected from the source typography. Pages 1–7 are the contents listing, replaced by the navigable index; page 324 is a PDF software advertisement. These exclusions are not missing biography pages. The PDF page position is canonical: physical PDF page 30 has an erroneous printed footer of 29.

## Reproduce extraction

With Python and PyMuPDF installed, run from the repository root:

```sh
python scripts/extract_seerah.py /path/to/English_ArRaheeq_AlMakhtum_THE_SEALED_NECTAR.pdf seerah/data.json.gz
```

The JSON records the source SHA-256. Extraction removes margin headers/page labels and joins wrapped text within PDF blocks. It makes no spelling, theological, quotation or citation substitutions. Every non-whitespace body character was checked against the PDF's extracted text on all 316 included pages. The original source's errors remain for a separately reviewed correction pass.

## Reader and search

- `/seerah`: chapters and sections, plus the existing account's Continue Reading link.
- `/seerah/page/44`: a stable PDF-page URL, with previous/next pages, chapter links and a page jump.
- `/seerah/page/44?section=block-1#block-1`: section-specific navigation. Validated headings are stored in reading progress, including their anchor.
- Reading progress uses the existing `seerah` source key, one last location per signed-in user. Anonymous reading does not create account history, matching other sources.
- The global search, public search API and assistant's existing search tool receive page-linked Seerah results through `db.SearchAll`.
- The SQLite FTS index uses Unicode tokenization and a content hash; rebuilds are atomic. Reader data is immutable after loading. Page URLs do not depend on text hashes.

Tests cover dataset completeness, chapter/page anchors, retained citations, search, repeated indexing, per-user progress, reader boundaries and invalid section targets.
