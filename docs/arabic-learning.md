# Arabic learning

The existing `data/arabic.zip` contains 21,247 individual Quranic word forms.
Inspection found no Arabic entries containing whitespace; English glosses can
contain multiple words. Frequency levels are vocabulary bands, not graded texts.

`data/arabic_learning.zip` holds `lessons.json`: 12 original standard-Arabic
sentence examples in three stages and three starter root families (ktb, drs, fth).
These are teaching examples, not Quran quotations or a comprehensive course.
Root glosses and pattern explanations are editorial learning material. Compare
Quranic uses at https://corpus.quran.com/qurandictionary.jsp?q=ktb and the corpus
morphology documentation. Also see
https://corpus.quran.com/qurandictionary.jsp?q=drs and
https://corpus.quran.com/qurandictionary.jsp?q=ftH. Everyday place nouns are not claimed to occur in the Quran.

Sentence pronunciation includes case endings for study. Root headwords use
citation forms. A root does not determine a word's exact meaning.

Runtime code is in `internal/arabiclearning`; pages use the existing Arabic
reading-progress key and standard notes/chat forms. No model calls or background
processing are required. Matching vocabulary entries to roots uses explicit
forms after removing vocalization and normalising alif wasla. It deliberately
does not guess roots by removing arbitrary prefixes or matching substrings.

To edit, unzip lessons.json, edit the UTF-8 JSON, and repack using
`scripts/arabic/pack.py lessons.json`. Keep slugs stable: they are reading-progress
URLs. Tests check references, root matching, routes, rendering and progress.
