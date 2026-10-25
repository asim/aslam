#!/usr/bin/env python3
"""Enrich the existing vocabulary from corpus morphology and source word positions.
Usage: python scripts/arabic/enrich.py /path/to/quranic-corpus-morphology-0.4.txt
The downloaded corpus is retained verbatim, including its copyright notices.
"""
import collections
import json
import pathlib
import re
import sys
import unicodedata
import zipfile

BASE = pathlib.Path(__file__).resolve().parents[2]
BW = dict(zip("'|>&<}AbptvjHxd*rzs$SDTZEgfqklmnhwYyFNKaui~o`{", "ءآأؤإئابتةثجحخدذرزسشصضطظعغفقكلمنهويىًٌٍَُِّْٰا"))
# Explicit dictionary avoids relying on the order of similar Arabic letters.
BW.update({'Y':'ى','y':'ي','{':'ٱ','p':'ة','t':'ت','^':'ٓ','#':'ٔ','@':'۟'})
def arabic(s):
    return ''.join(BW.get(c, c) for c in s)
# Keep letters only; corpus and source use different Quranic annotation marks.
def normalized(s):
    s=s.replace('ٰ','ا').replace('ٱ','ا').replace('ى','ي')
    return ''.join(c for c in s if unicodedata.category(c).startswith('L') and c!='ـ')

def main():
    raw=pathlib.Path(sys.argv[1]).read_bytes()
    positions={}
    for line in raw.decode('utf-8-sig').splitlines():
        if not line.startswith('('): continue
        location,form,tag,features=line.split('\t')
        ch,v,w,segment=map(int,re.findall(r'\d+',location))
        item=positions.setdefault((ch,v,w),{'form':'','roots':[]})
        item['form']+=arabic(form)
        root=re.search(r'(?:^|\|)ROOT:([^|]+)',features)
        lemma=re.search(r'(?:^|\|)LEM:([^|]+)',features)
        if root:
            item['roots'].append({'code':root[1],'arabic':arabic(root[1]),'lemma':arabic(lemma[1]) if lemma else '', 'type':tag})
    with zipfile.ZipFile(BASE/'data/arabic.zip') as z:
        vocab=json.loads(z.read('arabic_vocab.json'))
    with zipfile.ZipFile(BASE/'data/sources.zip') as z:
        chapters=json.loads(z.read('quran.json'))['chapters']
    by_form=collections.defaultdict(dict)
    passages=[]; matched=0; unmatched=0
    for ch in chapters:
        for v in ch['verses']:
            # Only numbered verses with word breakdowns; extra basmalas are not lessons.
            if v['number']<=0 or not v.get('words'): continue
            words=[]
            for i,w in enumerate(v['words'],1):
                annotation=positions.get((ch['number'],v['number'],i))
                roots=[]
                if annotation and normalized(annotation['form'])==normalized(w['arabic']):
                    roots=annotation['roots'];matched+=1
                else:
                    unmatched+=1

                for root in roots:
                    by_form[(w['arabic'],w['transliteration'])][(root['code'],root['lemma'],root['type'])]=root
                words.append(dict(w,roots=roots))
            passages.append({'chapter':ch['number'],'verse':v['number'],'title':ch['name']+' '+str(ch['number'])+':'+str(v['number']),'arabic':v['arabic'],'english':v['text'],'words':words})
    for word in vocab:
        word['roots']=list(by_form.get((word['arabic'],word['transliteration']),{}).values())
    if matched<70000: raise ValueError(f'Unexpected alignment coverage: {matched}')
    target=BASE/'data/arabic.zip'
    with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
        for name,content in [('arabic_vocab.json',json.dumps(vocab,ensure_ascii=False,separators=(',',':')).encode()),('arabic_passages.json',json.dumps(passages,ensure_ascii=False,separators=(',',':')).encode()),('quranic-corpus-morphology-0.4.txt',raw)]:
            info=zipfile.ZipInfo(name,date_time=(2026,10,25,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,content)
    print(f'{len(vocab)} existing forms preserved; {len(passages)} passages; {matched} aligned words; {unmatched} unaligned words left unannotated; {sum(bool(w["roots"]) for w in vocab)} forms with roots')
if __name__=='__main__': main()
