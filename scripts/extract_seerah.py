"""Extract the supplied Sealed Nectar PDF with narrowly reviewed source corrections.

Usage: python scripts/extract_seerah.py input.pdf seerah/data.json.gz [seerah/question-mark-review.md]
Requires PyMuPDF. Only repeated margin text and the PDF-tool advertisement
are excluded; original PDF page numbers and references are retained.
"""
import gzip
import hashlib
import json
import pathlib
import re
import sys
import fitz

def correct_source_text(text):
    # The PDF visibly contains these damaged names; never replace arbitrary '?'.
    text = re.sub(r"(?<!\w)All\?(?=\s|$)", "Allah", text)
    text = re.sub(r"(?<!\w)Qur’\?(?=\s|$)", "Qur’an", text)
    text = text.replace("reward the Muhsin? (good-doers,", "reward the Muhsinin (good-doers,")
    text = re.sub(r"\bAllah u(?= Akbar\b)", "Allahu", text)
    text = re.sub(r"\bQur’an ic\b", "Qur’anic", text)
    return re.sub(r"(\bAllah|\bQur’an) +(?=[,.;:!?)]|[’']s\b)", r"\1", text)


def main():
    source, output = map(pathlib.Path, sys.argv[1:3])
    doc = fitz.open(source)
    if len(doc) != 324:
        raise SystemExit("Expected the reviewed 324-page edition")
    chapters = [{"title": title, "page": page} for _, title, page in doc.get_toc() if 8 <= page <= 323]
    pages = []
    original_pages = []
    for number in range(8, 324):
        blocks = []
        original_blocks = []
        for block in doc[number - 1].get_text("dict", sort=True)["blocks"]:
            lines = []
            spans = []
            for line in block.get("lines", []):
                # The running header is above y=60 and page number below y=730.
                if line["bbox"][1] < 60 or line["bbox"][1] > 730:
                    continue
                text = "".join(s["text"] for s in line["spans"]).strip()
                if text:
                    lines.append(text)
                    spans.extend(s for s in line["spans"] if s["text"].strip())
            if not lines:
                continue
            original = " ".join(" ".join(lines).split())
            text = correct_source_text(original)
            heading = all("Bold" in s["font"] for s in spans) and max(s["size"] for s in spans) >= 11.5
            blocks.append({"text": text, "heading": heading, "id": "block-" + str(len(blocks) + 1)})
            original_blocks.append(dict(blocks[-1], text=original))
        chapter = max(i for i, ch in enumerate(chapters) if ch["page"] <= number)
        pages.append({"number": number, "chapter": chapter, "blocks": blocks})
        original_pages.append({"number": number, "blocks": original_blocks})
    assert len(pages) == 316 and all(p["blocks"] for p in pages)
    data = {"title": "The Sealed Nectar", "author": "Safiur Rahman al-Mubarakpuri", "translator": "Issam Diab", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "chapters": chapters, "pages": pages}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(gzip.compress((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode(), mtime=0))
    if len(sys.argv) > 3:
        from seerah_question_marks import write_audit
        write_audit(original_pages, pathlib.Path(sys.argv[3]), data["source_sha256"])
    print(f"Extracted {len(pages)} pages, {len(chapters)} chapter bookmarks, {sum(b['heading'] for p in pages for b in p['blocks'])} headings")


if __name__ == "__main__":
    main()
