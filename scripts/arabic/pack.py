#!/usr/bin/env python3
"""Pack reviewed Arabic lessons without embedding content in extraction code."""
import json
import pathlib
import sys
import zipfile

content = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = pathlib.Path(__file__).resolve().parents[2] / 'data/arabic_learning.zip'
with zipfile.ZipFile(target, 'w') as archive:
    entry = zipfile.ZipInfo('lessons.json', date_time=(2026, 10, 25, 0, 0, 0))
    entry.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(entry, json.dumps(content, ensure_ascii=False, indent=2) + '\n')
