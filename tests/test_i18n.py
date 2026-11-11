"""Каждая русская фраза index.html есть в словаре i18n-dict.js (иначе в EN/HE она останется по-русски)."""
import re
from html.parser import HTMLParser
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "web"
CYR = re.compile(r"[А-Яа-яЁё]")


def dict_keys():
    text = (WEB / "js" / "i18n-dict.js").read_text(encoding="utf-8")
    keys = re.findall(r'^\s*"((?:[^"\\]|\\.)*)":', text, flags=re.M)
    return {" ".join(k.split()) for k in keys}, text


class Phrases(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found, self.skip = set(), 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        for k, v in attrs:
            if k in ("placeholder", "title") and v and CYR.search(v):
                self.found.add(" ".join(v.split()))

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip -= 1

    def handle_data(self, data):
        d = " ".join(data.split())
        if not self.skip and CYR.search(d):
            self.found.add(d)


def test_index_html_fully_translated():
    keys, _ = dict_keys()
    p = Phrases()
    p.feed((WEB / "index.html").read_text(encoding="utf-8"))
    missing = sorted(x for x in p.found if x not in keys and x.rstrip(":") not in keys)
    assert not missing, missing


def test_every_entry_has_en_and_he():
    _, text = dict_keys()
    for m in re.finditer(r'^\s*"((?:[^"\\]|\\.)*)":\s*(\[[^\]]*\])', text, flags=re.M | re.S):
        vals = re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2))
        assert len(vals) == 2 and all(vals), m.group(1)
        # переменные шаблона сохраняются в обоих переводах
        names = set(re.findall(r"\{(\w+)\}", m.group(1)))
        for v in vals:
            assert set(re.findall(r"\{(\w+)\}", v)) == names, (m.group(1), v)


def test_no_duplicate_keys():
    import collections
    text = (WEB / "js" / "i18n-dict.js").read_text(encoding="utf-8")
    keys = re.findall(r'^\s*"((?:[^"\\]|\\.)*)":', text, flags=re.M)
    assert [k for k, n in collections.Counter(keys).items() if n > 1] == []
