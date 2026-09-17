"""Literal damaged fragments checked against the archive's scanned pages.

Page numbers below are printed scan pages, not reader URLs. Longer fragments
must precede their components. This table is not a general spelling normalizer.
"""
import re

VERIFIED = [
    ("Iq? at-as-Sal?", "Iqâmat-as-Salât", "111"),
    ("Al-K? ir?", "Al-Kâfirûn", "92"),
    ("Al-H? qah", "Al-Hâqqah", "110"),
    ("T?H?/i>", "Tâ-Hâ", "111"),
    ("L?il? a", "Lâ ilâha", "111"),
    ("H?M?", "Hâ-Mîm", "115"),
    ("Tham?", "Thamûd", "16, 116"),
    ("Taim?#146;", "Taimâ’", "22"),
    ("H? (a stallion", "Hâm (a stallion", "37"),
    ("Al-Ahs?#146;", "Al-Ahsâ’", "41"),
    ("Da’?", "Da’ûd", "43, 44"),
    ("Sulaim?", "Sulaimân", "56"),
    ("Mahm?", "Mahmûd", "56"),
    ("S? ah", "Sûrah", "72, 78, 81, 99–100, 103, 110"),
    ("Sal?", "Salât", "72, 78"),
    ("Isr?#146;", "Isrâ’", "72"),
    ("Abdull?", "Abdullâh", "78"),
    ("Shu‘ar?/i>", "Shu‘arâ", "81"),
    ("Al-Mushrik?", "Al-Mushrikûn", "84"),
]


def apply_verified(text):
    for damaged, corrected, _ in VERIFIED:
        # Remove only an attached gap before punctuation, not word separators.
        text = re.sub(re.escape(damaged) + r" +(?=[,.;:!?)]|[’']s\b)",
                      lambda _: corrected, text)
        text = text.replace(damaged, corrected)
    return text
