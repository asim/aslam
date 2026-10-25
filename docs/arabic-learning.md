# Arabic roots and contextual reading

The vocabulary added in commit 22c8eb4 was extracted from the word-by-word
Qur’an data. `data/sources.zip` already supplies the full verse text, translation,
word glosses and pronunciation. The reading pages reuse that material; they are
not an authored sentence course. Passage lengths (1–5, 6–10, 11+ words) are
navigation aids, not claims about grammatical completeness or difficulty.

## Data and provenance

The existing `data/arabic.zip` now contains:

- `arabic_vocab.json`: the same 21,247 records in the same order, with additional
  sourced root/lemma/part-of-speech annotations. Existing fields are unchanged.
- `arabic_passages.json`: 6,236 numbered verses and their word breakdowns,
  extracted from `data/sources.zip`. Extra basmalas are excluded.
- `quranic-corpus-morphology-0.4.txt`: the unmodified source annotations, including
  the complete copyright and terms-of-use header.

Morphology: Quranic Arabic Corpus v0.4, © 2011 Kais Dukes, GPL.
Official source and terms: https://corpus.quran.com/download/
Documentation: https://corpus.quran.com/documentation/
The corpus builds on Tanzil text: https://tanzil.net (CC BY-ND 3.0).
Retrieved verbatim from the public mirror:
https://raw.githubusercontent.com/taziksh/quran-frequencies/main/data/quranic-corpus-morphology-0.4.txt
The complete original notices are retained inside the archive. The UI attributes
and links the corpus and Tanzil. Original verse text is not rewritten.

Reproduce with `python scripts/arabic/enrich.py /path/to/quranic-corpus-morphology-0.4.txt`.
The script joins by chapter, verse and word position, then verifies the word's
letters after removing annotation marks and normalising known orthographic
variants (alif wasla, dagger alif, final ya/alif maqsura). It does not infer roots
from substrings. 74,917 words align; 2,514 do not and remain unannotated.
18,883 vocabulary forms have annotations across 1,626 roots. Some particles have
no root. A form can have multiple sourced analyses; all are retained.

Roots are displayed with corpus Buckwalter codes (e.g. ktb) and Arabic letters.
Lemmas are dictionary forms, and POS tags link to the corpus guide. Root pages
link directly to stored vocabulary IDs, so inflection does not break navigation.
This is Qur’anic vocabulary: everyday words absent from the source, such as
maktaba, are not invented or presented as corpus entries.

## Application integration

`loadArabic` uses the existing versioned source import. Database functions live
in `db/arabic_learning.go`, handlers and templates alongside the other Arabic
pages in `internal/server`. There is no new runtime package or sample archive.
The import preserves existing word IDs, updates roots and passages transactionally,
and commits the version marker only on success. No model generation or live
external fetch is involved. Bounded, context-aware SQLite queries serve readers;
root and passage indexes paginate 50 rows at a time.

Reading progress shares the existing `arabic` key. Root pagination is included
in its saved URL. Source pages use the existing Save/Chat forms, word links and
full-verse links. Existing `/arabic/{id}` URLs continue to work.

## Walking through the content

Root readers show one representative vocabulary form per lemma, chosen by
frequency and then stable word ID. This keeps inflection variants from crowding
out other words in the family. Grammar tags and corpus codes remain in the
underlying source data; the default reader shows Arabic, pronunciation and meaning.
Previous/Next walks roots in the same order as their index. Separate earlier/more
word links paginate unusually large families. The index link returns to the root's
list page.

Passage readers walk in length, chapter and verse order within the current length
band. Index links retain that band and return to the relevant 50-item page.
Reading progress continues to save the current root or passage URL.

## Import memory check

The source upgrade streams each vocabulary entry and passage from the ZIP JSON
arrays into the transaction. It retains lookup maps for stable word IDs but no
longer retains both decoded archives or their JSON buffers at once.

A local isolated fresh-database import on 2026-10-25, using separately compiled
Go test subprocesses and Linux child-process peak RSS, measured approximately
100.0 MiB before streaming and 31.7 MiB after. Post-GC Go heap was 0.5–0.6 MiB;
elapsed import times were 3.8 and 4.2 seconds. These are one-run local import
measurements, not estimates of the live server's total RSS or a performance gate.
