"""Reviewed question-mark audit for this PDF edition; suggestions are not edits."""
import collections
import html
import re

# Match whole damaged fragments, including multi-question-mark fragments.
# Proposed readings are contextual inferences, not verified edition transcriptions.
SUGGESTIONS = {
    "Tham?": "Thamud — tribal name; also named in the quoted 41:13 passage",
    "Muzaiqb?#146;": "Possibly Muzaiqiya — personal name; check another edition",
    "Taim?#146;": "Tayma / Taima — place name; verify transliteration",
    "H? (a stallion": "Ham — camel category in Qur’an 5:103; verify transliteration",
    "Al-Ahs?#146;": "Al-Ahsa — place name; verify ending and transliteration",
    "Da’?": "Dawud / Da’ud — Abu Dawud in the reporting context",
    "Sulaim?": "Sulaiman — personal name; verify spelling against another edition",
    "Mahm?": "Mahmud — personal name; verify spelling against another edition",
    "S? ah": "Surah — chapter label; join the split word",
    "Sal?": "Salat — prayer; verify the edition’s transliteration",
    "Moses ? ?": "Likely a lost honorific after Moses; exact text unknown",
    "???": "Likely continuation of the lost honorific after Moses; exact text unknown",
    "Isr?#146;": "Isra’ — chapter 17 title; damaged ending/entity",
    "Abdull?": "Abdullah — personal name",
    "Shu‘ar?/i>": "Shu‘ara’ — chapter 26 title; remove damaged markup after verification",
    "Al-Mushrik?": "Al-Mushrikun — plural defined as polytheists in 15:94",
    "Al-K? ir?": "Al-Kafirun — chapter 109 address; join split word after verification",
    "Al-H? qah": "Al-Haqqah — chapter 69 title; join split word",
    "T?H?/i>": "Ta-Ha — chapter 20 title; damaged letters and markup",
    "L?il? a": "La ilaha — transliteration in quoted 20:14; verify whole phrase",
    "Iq? at-as-Sal?": "Iqamat-as-Salat — prayer expression in 20:14; verify whole phrase",
    "H?M?": "Ha-Mim — opening letters of chapter 41",
}


def decision(text, position):
    for pattern, replacement in [(r"(?<=‘Imran bin ‘Amr )Muzaiqb\?#146;", "Muzaiqbâ’"),
                                 (r"(?<=It was a privilege granted to Moses )\? \?", "عليه السلام"),
                                 (r"^\?\?\?(?= and clearly attested in the Qur’\?)", "Continuation of the same honorific; removed"),
                                 (r"(?<!\w)All\?(?=\s|$)", "Allah"),
                                 (r"(?<!\w)Qur’\?(?=\s|$)", "Qur’an"),
                                 (r"(?<=reward the )Muhsin\?(?= \(good-doers,)", "Muhsinûn")]:
        for match in re.finditer(pattern, text):
            if match.start() <= position < match.end():
                return "Fixed", replacement + " — confirmed damaged term; surrounding spacing/split suffix repaired"
    # Longer matches take precedence over generic Sal? etc.
    for fragment in sorted(SUGGESTIONS, key=len, reverse=True):
        for match in re.finditer(re.escape(fragment), text):
            if match.start() <= position < match.end():
                return "Review", SUGGESTIONS[fragment]
    return "Keep", "Logical question in context; retain punctuation"


def escape(text):
    return html.escape(text, quote=False).replace("|", "&#124;")


def write_audit(pages, output, source_hash):
    entries = []
    passages = []
    for page in pages:
        for block in page["blocks"]:
            text = block["text"]
            rows = []
            for local, match in enumerate(re.finditer(r"\?", text), 1):
                position = match.start()
                status, reason = decision(text, position)
                excerpt = ("…" if position > 80 else "") + text[max(0, position-80):position] + "【?】" + text[position+1:position+81] + ("…" if position+81 < len(text) else "")
                entry = (len(entries)+1, page["number"], block["id"], local, position+1, status, reason, excerpt)
                entries.append(entry)
                rows.append(entry)
            if rows:
                passages.append((page["number"], block["id"], text, rows))
    counts = collections.Counter(row[5] for row in entries)
    lines = ["# Seerah question-mark review", "",
             f"Source PDF SHA-256: `{source_hash}`.", "",
             f"{len(entries)} original question marks: {counts['Fixed']} fixed, {counts['Review']} flagged for review, {counts['Keep']} retained as logical questions.", "",
             "Ordered by PDF page, extraction block, then character position. Each occurrence has a global number, an in-passage question-mark number and a one-based character position in the original text. Full passages below preserve sentence order without guessing sentence boundaries. 【?】 marks the target occurrence in excerpts.", "",
             "Fixed: Allah and Qur’an, including split suffixes and spacing, plus Muhsinûn, Muzaiqbâ’ and the honorific عليه السلام after Moses. The latter three are verified visually against printed pages 18, 16 and 72 of the [archive scan](https://archive.org/details/TheSealedNectar-Alhamdulillah-library.blogspot.in.pdf). Muhsinûn supersedes the earlier inferred Muhsinin reading. Review suggestions are contextual inferences, not applied changes or verified transcriptions. Keep decisions reflect a contextual review of this edition, not a general-purpose punctuation detector.", "",
             "## Remaining suspected corruption, in reading order", "",
             "| # | PDF page / block | ? in passage / character | Context | Proposed reading (not applied) |", "| --- | --- | --- | --- | --- |"]
    for n, page, block, local, char, status, reason, excerpt in entries:
        if status == "Review":
            lines.append(f"| {n} | {page} / {block} | {local} / {char} | {escape(excerpt)} | {escape(reason)} |")
    lines += ["", "## Every occurrence, with full original passages", ""]
    for page, block, text, rows in passages:
        lines += [f"### PDF page {page}, {block}", "", f"[Open passage](https://aslam.org/seerah/page/{page}#{block})", "", "> " + escape(text), "",
                  "| # | ? in passage | Character | Decision | Reading / reason |", "| --- | --- | --- | --- | --- |"]
        for n, _, _, local, char, status, reason, _ in rows:
            lines.append(f"| {n} | {local} | {char} | {status} | {escape(reason)} |")
        lines.append("")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n")
    print(f"Question-mark audit: {dict(counts)}")
