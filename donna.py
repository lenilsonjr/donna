#!/usr/bin/env python3
"""donna — the law layer. Versioned, hash-anchored legal corpus with a resolver
and quote verifier. See SPEC.md; v0 covers the Ireland (eISB) adapter.

Usage:
  donna.py ingest ie/2018/act/7            fetch + parse + store + attest
  donna.py resolve "s 42 DPA 2018"         citation -> canonical id
  donna.py text <id>                       canonical text of fragment/expression
  donna.py status <id>                     provenance: hashes, attestation, checks
  donna.py quote <fragment-id> "<text>"    exit 0 iff verbatim (typographic tolerance)
  donna.py search "<query>"                lexical FTS over fragments
  donna.py diff <id> <id>                  unified diff of two fragments

All ids follow {jur}/{year}/{type}/{num}@{version}:{lang}#{fragment}.
"""
import argparse, difflib, hashlib, json, re, sqlite3, sys, unicodedata, urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

PARSER_ID = "donna-ie/0.1.0"
UA = "donna/0.1 (open legal corpus tool; +https://github.com/lenilsonjr)"

# ---------------------------------------------------------------- storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS works(
  id TEXT PRIMARY KEY, jurisdiction TEXT, type TEXT, year INTEGER,
  number TEXT, title TEXT);
CREATE TABLE IF NOT EXISTS expressions(
  id TEXT PRIMARY KEY, work_id TEXT REFERENCES works(id), version TEXT,
  lang TEXT, source_url TEXT, content_hash TEXT, ingested_at TEXT);
CREATE TABLE IF NOT EXISTS fragments(
  id TEXT PRIMARY KEY, expression_id TEXT REFERENCES expressions(id),
  kind TEXT, number TEXT, heading TEXT, text TEXT, ord INTEGER,
  content_hash TEXT);
CREATE TABLE IF NOT EXISTS attestations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, expression_id TEXT, source_url TEXT,
  fetched_at TEXT, raw_sha256 TEXT, parser TEXT, checks_json TEXT);
"""
FTS = """
CREATE VIRTUAL TABLE IF NOT EXISTS fragments_fts
  USING fts5(id UNINDEXED, heading, text);
"""

HAS_FTS = True

def db_open(path):
    global HAS_FTS
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    try:
        con.executescript(FTS)
    except sqlite3.OperationalError:
        HAS_FTS = False
    return con

# ---------------------------------------------------------------- canonical text

def sha256(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()

def canonical(text):
    text = unicodedata.normalize("NFC", text)
    lines = [re.sub(r"[ \t]+", " ", l).strip() for l in text.splitlines()]
    return "\n".join(l for l in lines if l)

TYPOGRAPHIC = str.maketrans({"‘": "'", "’": "'", "“": '"',
                             "”": '"', "—": "-", "–": "-",
                             " ": " "})

def quote_normal(text):
    return re.sub(r"\s+", " ", text.translate(TYPOGRAPHIC)).strip()

# ---------------------------------------------------------------- Ireland adapter

IE_EMPTY = {"emdash": "—", "odq": "“", "cdq": "”", "osq": "‘",
            "csq": "’", "euro": "€", "hr1": "", "graphic": "",
            "afada": "á", "efada": "é", "ifada": "í",
            "ofada": "ó", "ufada": "ú", "cafada": "Á",
            "cefada": "É", "cifada": "Í", "cofada": "Ó",
            "cufada": "Ú", "marker": ""}

def ie_url(year, num):
    return f"https://www.irishstatutebook.ie/eli/{year}/act/{num}/enacted/en/xml"

def _fixup_xml(raw):
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"<!DOCTYPE[^>]*>", "", text)
    return re.sub(r"&(?!(amp|lt|gt|quot|apos);)(\w+);", r"[\2]", text)

def _serialize(el, out, fn_count):
    if el.tag == "fn":
        fn_count[0] += 1
        if el.tail:
            out.append(el.tail)
        return
    if el.tag in IE_EMPTY:
        out.append(IE_EMPTY[el.tag])
    if el.text:
        out.append(el.text)
    for child in el:
        _serialize(child, out, fn_count)
    if el.tag in ("p", "tr"):
        out.append("\n")
    if el.tag == "td":
        out.append(" | ")
    if el.tail:
        out.append(el.tail)

def _el_text(el, fn_count=None):
    out, fc = [], fn_count if fn_count is not None else [0]
    _serialize(el, out, fc)
    return canonical("".join(out))

def ie_parse(raw):
    root = ET.fromstring(_fixup_xml(raw))
    meta = root.find("metadata")
    work_meta = {
        "title": (meta.findtext("title") or "").strip(),
        "year": int(meta.findtext("year")),
        "number": meta.findtext("number").strip(),
        "type": "act",
    }
    fragments, fn_count = [], [0]
    for sect in root.iter("sect"):
        num_el, title_el = sect.find("number"), sect.find("title")
        number = (num_el.text or "").strip().rstrip(".") if num_el is not None else ""
        heading = _el_text(title_el) if title_el is not None else ""
        body = []
        for child in sect:
            if child.tag in ("number", "title"):
                continue
            body.append(_el_text(child, fn_count))
        fragments.append({"kind": "section", "number": number, "heading": heading,
                          "text": canonical("\n".join(body))})
    for i, sched in enumerate(root.iter("schedule"), 1):
        title_el = sched.find("title")
        heading = _el_text(title_el) if title_el is not None else f"Schedule {i}"
        body = [_el_text(c, fn_count) for c in sched if c.tag != "title"]
        fragments.append({"kind": "schedule", "number": str(i), "heading": heading,
                          "text": canonical("\n".join(body))})
    return work_meta, fragments, fn_count[0]

def ie_checks(fragments, fn_stripped):
    sections = [f for f in fragments if f["kind"] == "section"]
    numbers, gaps, empties = [], [], []
    for f in fragments:
        if not f["text"]:
            empties.append(f["number"])
        if f["kind"] == "section" and f["number"].isdigit():
            numbers.append(int(f["number"]))
    for a, b in zip(numbers, numbers[1:]):
        if b not in (a, a + 1):
            gaps.append(f"{a}->{b}")
    return {"sections": len(sections),
            "schedules": len(fragments) - len(sections),
            "numbering_gaps": gaps, "empty_fragments": empties,
            "footnotes_stripped": fn_stripped}

ADAPTERS = {"ie": {"tier": "A", "url": ie_url, "parse": ie_parse, "checks": ie_checks}}

# ---------------------------------------------------------------- ingest

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req) as r:
        return r.read()

def ingest(con, work_path):
    m = re.fullmatch(r"(\w+)/(\d{4})/(\w+)/(\w+)", work_path)
    if not m:
        sys.exit(f"work path must look like ie/2018/act/7, got {work_path!r}")
    jur, year, wtype, num = m.groups()
    adapter = ADAPTERS.get(jur)
    if not adapter:
        sys.exit(f"no adapter for jurisdiction {jur!r} (have: {', '.join(ADAPTERS)})")
    url = adapter["url"](year, num)
    raw = fetch(url)
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    work_meta, fragments, fn_stripped = adapter["parse"](raw)
    checks = adapter["checks"](fragments, fn_stripped)

    work_id = f"{jur}/{year}/{wtype}/{num}"
    expr_id = f"{work_id}@enacted:en"
    frag_rows, frag_hashes = [], []
    for i, f in enumerate(fragments):
        fid = f"{expr_id}#{'sec' if f['kind'] == 'section' else 'sched'}-{f['number']}"
        h = sha256(f["text"])
        frag_hashes.append(h)
        frag_rows.append((fid, expr_id, f["kind"], f["number"], f["heading"],
                          f["text"], i, h))
    expr_hash = sha256("\n".join(frag_hashes))

    with con:
        con.execute("INSERT OR REPLACE INTO works VALUES (?,?,?,?,?,?)",
                    (work_id, jur, work_meta["type"], work_meta["year"],
                     work_meta["number"], work_meta["title"]))
        con.execute("INSERT OR REPLACE INTO expressions VALUES (?,?,?,?,?,?,?)",
                    (expr_id, work_id, "enacted", "en", url, expr_hash, fetched_at))
        con.execute("DELETE FROM fragments WHERE expression_id = ?", (expr_id,))
        con.executemany("INSERT INTO fragments VALUES (?,?,?,?,?,?,?,?)", frag_rows)
        if HAS_FTS:
            con.execute("DELETE FROM fragments_fts WHERE id LIKE ?", (expr_id + "%",))
            con.executemany("INSERT INTO fragments_fts VALUES (?,?,?)",
                            [(r[0], r[4], r[5]) for r in frag_rows])
        con.execute("INSERT INTO attestations(expression_id, source_url, fetched_at,"
                    " raw_sha256, parser, checks_json) VALUES (?,?,?,?,?,?)",
                    (expr_id, url, fetched_at, sha256(raw), PARSER_ID,
                     json.dumps(checks)))
    print(f"{expr_id}  {work_meta['title']}")
    print(f"fragments: {len(frag_rows)}  expression_hash: {expr_hash[:16]}…")
    print(f"checks: {json.dumps(checks)}")
    if checks["numbering_gaps"] or checks["empty_fragments"]:
        print("WARNING: structure checks flagged issues", file=sys.stderr)

# ---------------------------------------------------------------- resolve

def acronym(title):
    words = [w for w in re.split(r"\W+", title) if w and not w.isdigit()
             and w.upper() not in ("OF", "AND", "THE", "AN", "A", "ACT")]
    return "".join(w[0].upper() for w in words) + "A"  # DATA PROTECTION -> DPA

def resolve(con, citation):
    c = citation.strip()
    m = re.search(r"irishstatutebook\.ie/eli/(\d{4})/act/(\d+)(?:/section/(\d+))?", c)
    if m:
        year, num, sec = m.groups()
        base = f"ie/{year}/act/{num}@enacted:en"
        return base + (f"#sec-{sec}" if sec else "")
    m = re.fullmatch(r"(\w+/\d{4}/\w+/\w+)(@[\w:]+)?(#[\w-]+)?", c)
    if m:
        path, version, frag = m.groups()
        return f"{path}{version or '@enacted:en'}{frag or ''}"
    m = re.search(r"(?:^|\b)(?:s\.?|section)\s*(\d+\w*)\s+(?:of\s+(?:the\s+)?)?(.+)", c,
                  re.IGNORECASE)
    sec, name = (m.group(1), m.group(2).strip()) if m else (None, c)
    ym = re.search(r"(\d{4})\s*$", name)
    year = int(ym.group(1)) if ym else None
    name_key = re.sub(r"\d{4}\s*$", "", name).strip().upper()
    for work_id, title, wyear in con.execute("SELECT id, title, year FROM works"):
        if year and wyear != year:
            continue
        if name_key and name_key not in title.upper() and name_key != acronym(title):
            continue
        expr = f"{work_id}@enacted:en"
        return expr + (f"#sec-{sec}" if sec else "")
    sys.exit(f"cannot resolve {citation!r}")

# ---------------------------------------------------------------- read verbs

def get_fragment(con, fid):
    row = con.execute("SELECT id, heading, text, content_hash, expression_id"
                      " FROM fragments WHERE id = ?", (fid,)).fetchone()
    if not row:
        sys.exit(f"unknown fragment {fid!r} (is the Work ingested?)")
    return row

def cmd_text(con, ident):
    if "#" in ident:
        _, heading, text, _, _ = get_fragment(con, ident)
        print(heading + "\n" if heading else "", end="")
        print(text)
    else:
        rows = con.execute("SELECT heading, text FROM fragments WHERE expression_id = ?"
                           " ORDER BY ord", (ident,)).fetchall()
        if not rows:
            sys.exit(f"unknown expression {ident!r}")
        for heading, text in rows:
            print((heading + "\n" if heading else "") + text + "\n")

def cmd_status(con, ident):
    expr_id = ident.split("#")[0]
    expr = con.execute("SELECT e.id, w.title, e.source_url, e.content_hash,"
                       " e.ingested_at FROM expressions e JOIN works w"
                       " ON w.id = e.work_id WHERE e.id = ?", (expr_id,)).fetchone()
    if not expr:
        sys.exit(f"unknown expression {expr_id!r}")
    print(f"expression: {expr[0]}\ntitle:      {expr[1]}\nsource:     {expr[2]}")
    print(f"expr_hash:  {expr[3]}\ningested:   {expr[4]}")
    if "#" in ident:
        frag = get_fragment(con, ident)
        print(f"fragment:   {frag[0]}\nfrag_hash:  {frag[3]}")
    att = con.execute("SELECT fetched_at, raw_sha256, parser, checks_json FROM"
                      " attestations WHERE expression_id = ? ORDER BY id DESC",
                      (expr_id,)).fetchone()
    if att:
        print(f"attested:   {att[0]}  parser {att[2]}\nraw_sha256: {att[1]}")
        print(f"checks:     {att[3]}")

def cmd_quote(con, fid, text):
    _, _, body, _, _ = get_fragment(con, fid)
    needle, hay = quote_normal(text), quote_normal(body)
    if needle in hay:
        print(f"VERIFIED: quote appears verbatim in {fid}")
        return 0
    words = hay.split()
    n = max(len(needle.split()), 4)
    windows = [" ".join(words[i:i + n]) for i in range(0, max(len(words) - n + 1, 1))]
    best = difflib.get_close_matches(needle, windows, n=1, cutoff=0)
    print(f"NOT VERIFIED: quote not found in {fid}", file=sys.stderr)
    if best:
        print(f"nearest text: {best[0][:300]}", file=sys.stderr)
    return 1

def cmd_search(con, query):
    if HAS_FTS:
        rows = con.execute("SELECT id, heading, snippet(fragments_fts, 2, '[', ']',"
                           " '…', 12) FROM fragments_fts WHERE fragments_fts MATCH ?"
                           " ORDER BY rank LIMIT 10", (query,)).fetchall()
    else:
        rows = con.execute("SELECT id, heading, substr(text, 1, 80) FROM fragments"
                           " WHERE text LIKE ? LIMIT 10", (f"%{query}%",)).fetchall()
    for fid, heading, snip in rows:
        print(f"{fid}\n  {heading}\n  {snip}")
    if not rows:
        sys.exit("no matches")

def cmd_diff(con, a, b):
    fa, fb = get_fragment(con, a), get_fragment(con, b)
    out = difflib.unified_diff(fa[2].splitlines(), fb[2].splitlines(),
                               fromfile=a, tofile=b, lineterm="")
    print("\n".join(out) or "identical")

# ---------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(prog="donna", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="donna.db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ingest").add_argument("work")
    sub.add_parser("resolve").add_argument("citation")
    sub.add_parser("text").add_argument("id")
    sub.add_parser("status").add_argument("id")
    q = sub.add_parser("quote"); q.add_argument("id"); q.add_argument("text")
    sub.add_parser("search").add_argument("query")
    d = sub.add_parser("diff"); d.add_argument("a"); d.add_argument("b")
    args = ap.parse_args()
    con = db_open(args.db)
    if args.cmd == "ingest":
        ingest(con, args.work)
    elif args.cmd == "resolve":
        print(resolve(con, args.citation))
    elif args.cmd == "text":
        cmd_text(con, args.id)
    elif args.cmd == "status":
        cmd_status(con, args.id)
    elif args.cmd == "quote":
        sys.exit(cmd_quote(con, args.id, args.text))
    elif args.cmd == "search":
        cmd_search(con, args.query)
    elif args.cmd == "diff":
        cmd_diff(con, args.a, args.b)

if __name__ == "__main__":
    main()
