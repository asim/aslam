"""Extract the supplied Sealed Nectar PDF without editorial substitutions.

Usage: python scripts/extract_seerah.py input.pdf seerah/data.json.gz
Requires PyMuPDF. Only repeated margin text and the PDF-tool advertisement
are excluded; original PDF page numbers and references are retained.
"""
import gzip
import hashlib
import json
import pathlib
import sys
import fitz

source, output = map(pathlib.Path, sys.argv[1:])
doc = fitz.open(source)
if len(doc) != 324:
    raise SystemExit("Expected the reviewed 324-page edition")
chapters = [{"title": title, "page": page} for _, title, page in doc.get_toc() if 8 <= page <= 323]
pages = []
for number in range(8, 324):
    blocks = []
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
        text = " ".join(" ".join(lines).split())
        heading = all("Bold" in s["font"] for s in spans) and max(s["size"] for s in spans) >= 11.5
        blocks.append({"text": text, "heading": heading, "id": "block-" + str(len(blocks) + 1)})
    chapter = max(i for i, ch in enumerate(chapters) if ch["page"] <= number)
    pages.append({"number": number, "chapter": chapter, "blocks": blocks})
assert len(pages) == 316 and all(p["blocks"] for p in pages)
data = {"title": "The Sealed Nectar", "author": "Safiur Rahman al-Mubarakpuri", "translator": "Issam Diab", "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "chapters": chapters, "pages": pages}
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(gzip.compress((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode(), mtime=0))
print(f"Extracted {len(pages)} pages, {len(chapters)} chapter bookmarks, {sum(b['heading'] for p in pages for b in p['blocks'])} headings")
