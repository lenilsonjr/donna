#!/usr/bin/env python3
"""donna — the law layer. Versioned, hash-anchored legal corpus with a resolver
and quote verifier. See SPEC.md; adapters: ie (eISB + LRC), pt (Portal das
Finanças, configured works).

Usage:
  donna.py ingest ie/2018/act/7                fetch + parse + store + attest
  donna.py ingest ie/2018/act/7@revised        LRC Revised Act second Expression
  donna.py ingest pt/1988/dec-lei/442-b@consolidated   CIRC from Portal das Finanças
  donna.py resolve "s 42 DPA 2018"             citation -> canonical id
  donna.py resolve "art. 66.º CIRC"            Portuguese citation forms work too
  donna.py versions ie/2018/act/7              list Expressions of a Work
  donna.py text <id>                           canonical text
  donna.py status <id>                         provenance: hashes, attestation
  donna.py quote <fragment-id> "<text>"        exit 0 iff verbatim
  donna.py search "<query>"                    lexical FTS over fragments
  donna.py diff <id> <id>                      unified diff of two fragments

All ids follow {jur}/{year}/{type}/{num}@{version}:{lang}#{fragment}.
"""
import argparse, difflib, hashlib, html, json, os, re, sqlite3, subprocess
import sys, tempfile, time, unicodedata
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser

UA = "donna/0.3 (open legal corpus tool)"
KIND_PREFIX = {"section": "sec", "schedule": "sched", "article": "art"}

# ---------------------------------------------------------------- storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS works(
  id TEXT PRIMARY KEY, jurisdiction TEXT, type TEXT, year INTEGER,
  number TEXT, title TEXT, aliases TEXT DEFAULT '');
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
    cols = {r[1] for r in con.execute("PRAGMA table_info(attestations)")}
    for c in ("payload_json", "signature", "signer"):
        if c not in cols:
            con.execute(f"ALTER TABLE attestations ADD COLUMN {c} TEXT")
    return con

# ---------------------------------------------------------------- canonical text

def sha256(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()

def canonical(text):
    text = unicodedata.normalize("NFC", text).replace("\u00a0", " ")
    lines = [re.sub(r"[ \t]+", " ", l).strip() for l in text.splitlines()]
    return "\n".join(l for l in lines if l)

TYPOGRAPHIC = str.maketrans({"‘": "'", "’": "'", "“": '"',
                             "”": '"', "—": "-", "–": "-",
                             "\u00a0": " "})

def quote_normal(text):
    return re.sub(r"\s+", " ", text.translate(TYPOGRAPHIC)).strip()

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req) as r:
        return r.read()

def numbering_gaps(numbers):
    gaps = []
    for a, b in zip(numbers, numbers[1:]):
        if b not in (a, a + 1):
            gaps.append(f"{a}->{b}")
    return gaps

# ---------------------------------------------------------------- signing

KEY_DIR = ".donna"  # set from --db location in main()
SIG_NAMESPACE = "donna-attestation"

def _key_paths():
    return (os.path.join(KEY_DIR, "ingester_key"),
            os.path.join(KEY_DIR, "ingester_key.pub"))

def sign_payload(payload):
    """-> (sshsig, signer pubkey) or (None, None) when no ingester key exists."""
    key, pub = _key_paths()
    if not os.path.exists(key):
        return None, None
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "payload")
        with open(p, "wb") as fh:
            fh.write(payload)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", key,
                        "-n", SIG_NAMESPACE, "-q", p],
                       check=True, capture_output=True)
        with open(p + ".sig") as fh:
            sig = fh.read()
    with open(pub) as fh:
        kt_b64 = " ".join(fh.read().split()[:2])
    return sig, kt_b64

def verify_signature(payload, sig, signer):
    with tempfile.TemporaryDirectory() as td:
        allowed = os.path.join(td, "allowed_signers")
        sigf = os.path.join(td, "payload.sig")
        with open(allowed, "w") as fh:
            fh.write(f"donna-ingester {signer}\n")
        with open(sigf, "w") as fh:
            fh.write(sig)
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", allowed,
                            "-I", "donna-ingester", "-n", SIG_NAMESPACE,
                            "-s", sigf], input=payload, capture_output=True)
    return r.returncode == 0, (r.stderr or r.stdout).decode().strip()

# ---------------------------------------------------------------- Ireland adapter

IE_PARSER = "donna-ie/0.3.0"
IE_EMPTY = {"emdash": "—", "odq": "“", "cdq": "”", "osq": "‘",
            "csq": "’", "euro": "€", "hr1": "", "graphic": "",
            "afada": "á", "efada": "é", "ifada": "í",
            "ofada": "ó", "ufada": "ú", "cafada": "Á",
            "cefada": "É", "cifada": "Í", "cofada": "Ó",
            "cufada": "Ú", "marker": "", "bull": "•"}

def _ie_fixup_xml(raw):
    """Strip the DOCTYPE (resolving its internal-subset entities) and neutralize
    undefined entities. Entity values may carry markup; tags are dropped."""
    text = raw.decode("utf-8", errors="replace")
    entities = {}
    subset = re.search(r"<!DOCTYPE[^\[>]*\[(.*?)\]\s*>", text, re.S)
    if subset:
        for name, val in re.findall(r'<!ENTITY\s+(\w+)\s+"(.*?)"\s*>', subset.group(1), re.S):
            entities[name] = re.sub(r"<[^>]+>", "", val)
    text = re.sub(r"<!DOCTYPE[^\[>]*\[.*?\]\s*>|<!DOCTYPE[^>]*>", "", text,
                  count=1, flags=re.S)
    text = re.sub(r"&(?!(?:amp|lt|gt|quot|apos);)(\w+);",
                  lambda m: entities.get(m.group(1), f"[{m.group(1)}]"), text)
    return text, entities

def _ie_serialize(el, out, counts):
    if el.tag == "fn":
        counts["fn"] += 1
        if el.tail:
            out.append(el.tail.replace("\n", " "))
        return
    if el.tag == "div" and "annotation" in (el.get("class") or ""):
        counts["ann"] += 1
        if el.tail:
            out.append(el.tail.replace("\n", " "))
        return
    if el.tag in IE_EMPTY:
        out.append(IE_EMPTY[el.tag])
    if el.text:
        out.append(el.text.replace("\n", " "))
    for child in el:
        _ie_serialize(child, out, counts)
    if el.tag in ("p", "tr"):
        out.append("\n")
    if el.tag == "td":
        out.append(" | ")
    if el.tail:
        out.append(el.tail.replace("\n", " "))

def _ie_text(el, counts=None):
    out = []
    _ie_serialize(el, out, counts if counts is not None else {"fn": 0, "ann": 0})
    return canonical("".join(out))

def ie_acquire(year, wtype, num, version):
    if wtype != "act":
        sys.exit(f"ie adapter handles acts, got {wtype!r}")
    if version == "revised":
        url = f"https://revisedacts.lawreform.ie/eli/{year}/act/{num}/revised/en/xml"
    else:
        url = f"https://www.irishstatutebook.ie/eli/{year}/act/{num}/enacted/en/xml"
    raw = fetch(url)
    text, entities = _ie_fixup_xml(raw)
    root = ET.fromstring(text)
    meta = root.find("metadata")
    counts = {"fn": 0, "ann": 0}
    fragments = []
    for sect in root.iter("sect"):
        num_el, title_el = sect.find("number"), sect.find("title")
        number = (num_el.text or "").strip().rstrip(".") if num_el is not None else ""
        heading = _ie_text(title_el) if title_el is not None else ""
        body = [_ie_text(c, counts) for c in sect if c.tag not in ("number", "title")]
        fragments.append({"kind": "section", "number": number, "heading": heading,
                          "text": canonical("\n".join(body))})
    for i, sched in enumerate(root.iter("schedule"), 1):
        title_el = sched.find("title")
        heading = _ie_text(title_el) if title_el is not None else f"Schedule {i}"
        body = [_ie_text(c, counts) for c in sched if c.tag != "title"]
        fragments.append({"kind": "schedule", "number": str(i), "heading": heading,
                          "text": canonical("\n".join(body))})
    label = "enacted"
    if version == "revised":
        if "updatedtodate" not in entities:
            sys.exit("revised source did not declare an updated-to date")
        d = datetime.strptime(entities["updatedtodate"].strip(), "%d %B %Y").date()
        label = f"revised-{d.isoformat()}"
    seq = [int(f["number"]) for f in fragments
           if f["kind"] == "section" and f["number"].isdigit()]
    checks = {"tier": "A",
              "sections": sum(1 for f in fragments if f["kind"] == "section"),
              "schedules": sum(1 for f in fragments if f["kind"] == "schedule"),
              "numbering_gaps": numbering_gaps(seq),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]],
              "footnotes_stripped": counts["fn"],
              "annotations_stripped": counts["ann"]}
    return {"work_meta": {"title": (meta.findtext("title") or "").strip(),
                          "aliases": ""},
            "fragments": fragments, "label": label, "lang": "en",
            "source_url": url, "raw": raw, "checks": checks, "parser": IE_PARSER}

# ---------------------------------------------------------------- Portugal adapter

PT_PARSER = "donna-pt/0.6.0"
PT_BASE = "https://info.portaldasfinancas.gov.pt"
PT_WORKS = {
    ("1988", "dec-lei", "442-b"): {
        "title": "Código do Imposto sobre o Rendimento das Pessoas Coletivas"
                 " (Código do IRC)",
        "aliases": "CIRC,CODIGO DO IRC,CÓDIGO DO IRC",
        "index": PT_BASE + "/pt/informacao_fiscal/codigos_tributarios/CIRC_2R"
                 "/Pages/circ-codigo-do-irc-indice.aspx",
        "slug": "irc",
    },
}

class _PTBlocks(HTMLParser):
    """Collects p/div text blocks from a Portal das Finanças page, dropping
    em-wrapped redaction attributions and script/style content. Two page
    vintages exist: AT*Text classes, and inline text-align styles."""
    def __init__(self):
        super().__init__()
        self.blocks = []   # (hint, text, em_text)
        self.stack = []    # (tag, hint, buf, em_buf)
        self.em_depth = 0
        self.em_stripped = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("p", "div", "script", "style"):
            a = dict(attrs)
            hint = ((a.get("class") or "") + "|" + (a.get("style") or "")).lower()
            self.stack.append((tag, hint, [], []))
        elif tag == "em" and self.stack:
            self.em_depth += 1
            self.em_stripped += 1
        elif tag == "br" and self.stack and not self.em_depth:
            self.stack[-1][2].append("\n")

    def handle_endtag(self, tag):
        if tag == "em":
            self.em_depth = max(0, self.em_depth - 1)
        elif tag in ("p", "div", "script", "style") and self.stack:
            t, hint, buf, em_buf = self.stack.pop()
            if t in ("p", "div"):
                text = canonical("".join(buf))
                em_text = canonical("".join(em_buf))
                if text or em_text:
                    self.blocks.append((hint, text, em_text))

    def handle_data(self, data):
        if not self.stack or self.stack[-1][0] in ("script", "style"):
            return
        if self.em_depth:
            self.stack[-1][3].append(data)
        else:
            self.stack[-1][2].append(data)

PT_CHROME = ("container-wrapper", "ms-core-overlay", "linksinfo")

def _pt_extract(html_text):
    """-> (body, heading, em_stripped, notes_stripped) or (None, ...) when the
    article heading cannot be located."""
    parser = _PTBlocks()
    parser.feed(html_text)
    blocks = parser.blocks
    art_re = re.compile(r"Artigo\s+\d+\.?º?(?:\s*-\s*\w+)?")
    body_shape = re.compile(r"(?:\d+\s*[-—.]|[a-z]\)|\(|Artigo)")
    start = heading = body_from = None
    for require_center in (True, False):
        for i, (h, t, _) in enumerate(blocks):
            if require_center and "atcenteredtext" not in h \
                    and "text-align:center" not in h:
                continue
            lines = [l.strip() for l in t.split("\n")]
            art_at = next((k for k, l in enumerate(lines)
                           if art_re.match(l) and len(l) <= 40), None)
            if art_at is None:
                continue
            start = i
            rest = "\n".join(lines[art_at + 1:]).strip()
            nxt_hint, nxt = (blocks[i + 1][0], blocks[i + 1][1]) \
                if i + 1 < len(blocks) else ("", "")
            if rest:
                heading, body_from = rest, i + 1
            elif nxt and not body_shape.match(nxt) \
                    and ("center" in nxt_hint or "atcenteredtext" in nxt_hint
                         or len(nxt) < 120):
                heading, body_from = nxt, i + 2
            else:
                heading, body_from = "", i + 1
            break
        if start is not None:
            break
    if start is None:
        return None, "", parser.em_stripped, 0
    body, em_only, notes = [], [], 0
    for hint, txt, em_text in blocks[body_from:]:
        if any(c in hint for c in PT_CHROME) \
                or (txt or em_text).startswith("Links Úteis"):
            break
        if txt.startswith(("Nota -", "Nota-", "Nota:")) or "•••" in txt:
            notes += 1
            continue
        if txt:
            body.append(txt)
        elif em_text and "•••" not in em_text:
            em_only.append(em_text)
    if not body and em_only:
        # a revoked article's whole body is its em-wrapped status line
        body = em_only
    return canonical("\n".join(body)), heading, parser.em_stripped, notes

def pt_acquire(year, wtype, num, version):
    cfg = PT_WORKS.get((year, wtype, num))
    if not cfg:
        known = ", ".join("/".join(k) for k in PT_WORKS)
        sys.exit(f"pt adapter has no source configured for {year}/{wtype}/{num}"
                 f" (configured: {known})")
    if version != "consolidated":
        sys.exit("pt adapter serves @consolidated only")
    index_raw = fetch(cfg["index"])
    index_html = index_raw.decode("utf-8", errors="replace")
    seen, pages = set(), []
    for m in re.finditer(r'href="([^"]*?/pages/%s(\d+)([a-z]?)\.aspx)"' % cfg["slug"],
                         index_html, re.IGNORECASE):
        href, digits, letter = m.groups()
        number = digits + (f"-{letter.upper()}" if letter else "")
        if number in seen:
            continue
        seen.add(number)
        pages.append((number, PT_BASE + href if href.startswith("/") else href))
    if not pages:
        sys.exit("no article pages found in index — page layout may have changed")
    fragments, raw_parts = [], [index_raw]
    em_total = notes_total = 0
    unparsed = []
    for number, url in pages:
        raw = fetch(url)
        raw_parts.append(raw)
        body, heading, em_n, notes_n = _pt_extract(raw.decode("utf-8", errors="replace"))
        em_total += em_n
        notes_total += notes_n
        if body is None:
            unparsed.append(number)
            body = ""
        fragments.append({"kind": "article", "number": number, "heading": heading,
                          "text": body})
        time.sleep(0.25)
    seq = sorted({int(re.match(r"\d+", f["number"]).group(0)) for f in fragments})
    checks = {"tier": "B",
              "articles": len(fragments),
              "pages_fetched": len(pages) + 1,
              "numbering_gaps": numbering_gaps(seq),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]],
              "unparsed_pages": unparsed,
              "redaction_notes_stripped": em_total,
              "editorial_notes_stripped": notes_total}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "pt",
            "source_url": cfg["index"], "raw": b"".join(raw_parts),
            "checks": checks, "parser": PT_PARSER}

ADAPTERS = {"ie": ie_acquire, "pt": pt_acquire}

# ---------------------------------------------------------------- ingest

def ingest(con, work_path):
    m = re.fullmatch(r"([\w-]+)/(\d{4})/([\w-]+)/([\w-]+)"
                     r"(?:@(enacted|revised|consolidated))?", work_path)
    if not m:
        sys.exit(f"work path must look like ie/2018/act/7[@revised], got {work_path!r}")
    jur, year, wtype, num, version = m.groups()
    version = version or "enacted"
    adapter = ADAPTERS.get(jur)
    if not adapter:
        sys.exit(f"no adapter for jurisdiction {jur!r} (have: {', '.join(ADAPTERS)})")
    res = adapter(year, wtype, num, version)
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    work_id = f"{jur}/{year}/{wtype}/{num}"
    expr_id = f"{work_id}@{res['label']}:{res['lang']}"
    frag_rows, frag_hashes = [], []
    for i, f in enumerate(res["fragments"]):
        fid = f"{expr_id}#{KIND_PREFIX[f['kind']]}-{f['number']}"
        h = sha256(f["text"])
        frag_hashes.append(h)
        frag_rows.append((fid, expr_id, f["kind"], f["number"], f["heading"],
                          f["text"], i, h))
    expr_hash = sha256("\n".join(frag_hashes))

    with con:
        con.execute("INSERT OR REPLACE INTO works VALUES (?,?,?,?,?,?,?)",
                    (work_id, jur, wtype, int(year), num,
                     res["work_meta"]["title"], res["work_meta"]["aliases"]))
        con.execute("INSERT OR REPLACE INTO expressions VALUES (?,?,?,?,?,?,?)",
                    (expr_id, work_id, res["label"], res["lang"],
                     res["source_url"], expr_hash, fetched_at))
        con.execute("DELETE FROM fragments WHERE expression_id = ?", (expr_id,))
        con.executemany("INSERT INTO fragments VALUES (?,?,?,?,?,?,?,?)", frag_rows)
        if HAS_FTS:
            con.execute("DELETE FROM fragments_fts WHERE id LIKE ?", (expr_id + "#%",))
            con.executemany("INSERT INTO fragments_fts VALUES (?,?,?)",
                            [(r[0], r[4], r[5]) for r in frag_rows])
        payload = json.dumps(
            {"expression_id": expr_id, "source_url": res["source_url"],
             "fetched_at": fetched_at, "raw_sha256": sha256(res["raw"]),
             "content_hash": expr_hash, "parser": res["parser"],
             "checks": res["checks"]},
            sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        sig, signer = sign_payload(payload.encode())
        con.execute("INSERT INTO attestations(expression_id, source_url, fetched_at,"
                    " raw_sha256, parser, checks_json, payload_json, signature,"
                    " signer) VALUES (?,?,?,?,?,?,?,?,?)",
                    (expr_id, res["source_url"], fetched_at, sha256(res["raw"]),
                     res["parser"], json.dumps(res["checks"], ensure_ascii=False),
                     payload, sig, signer))
    print(f"{expr_id}  {res['work_meta']['title']}")
    print("attestation: signed (sshsig)" if sig else
          "attestation: UNSIGNED — run 'donna keygen' to sign future ingests")
    print(f"fragments: {len(frag_rows)}  expression_hash: {expr_hash[:16]}…")
    print(f"checks: {json.dumps(res['checks'], ensure_ascii=False)}")
    if res["checks"].get("numbering_gaps") or res["checks"].get("empty_fragments"):
        print("NOTE: structure checks recorded gaps or empty fragments", file=sys.stderr)

# ---------------------------------------------------------------- resolve

class DonnaError(Exception):
    """Verb-level failure surfaced as exit 1 on the CLI, isError over MCP."""

def acronym(title):
    words = [w for w in re.split(r"\W+", title) if w and not w.isdigit()
             and w.upper() not in ("OF", "AND", "THE", "AN", "A", "ACT")]
    return "".join(w[0].upper() for w in words) + "A"  # DATA PROTECTION -> DPA

def expression_for(con, work_id, version):
    row = con.execute("SELECT id FROM expressions WHERE work_id = ? AND version"
                      " LIKE ? ORDER BY version DESC",
                      (work_id, version + "%")).fetchone()
    if row:
        return row[0]
    rows = con.execute("SELECT id FROM expressions WHERE work_id = ?",
                       (work_id,)).fetchall()
    if len(rows) == 1:  # Q6 interim rule: fall back to the only Expression
        return rows[0][0]
    if rows:
        raise DonnaError(f"no {version} expression for {work_id!r}; have: "
                         + ", ".join(r[0] for r in rows))
    raise DonnaError(f"no expressions ingested for {work_id!r}")

def _fragment_id(con, expr, sec):
    for prefix in ("sec", "art"):
        fid = f"{expr}#{prefix}-{sec}"
        if con.execute("SELECT 1 FROM fragments WHERE id = ?", (fid,)).fetchone():
            return fid
    raise DonnaError(f"no fragment numbered {sec!r} in {expr}")

def q_resolve(con, citation):
    c = citation.strip()
    m = re.search(r"(?:irishstatutebook\.ie|revisedacts\.lawreform\.ie)"
                  r"/eli/(\d{4})/act/(\d+)(?:/section/(\d+\w*))?/(enacted|revised)", c)
    if m:
        year, num, sec, version = m.groups()
        expr = expression_for(con, f"ie/{year}/act/{num}", version)
        return {"id": _fragment_id(con, expr, sec) if sec else expr}
    m = re.fullmatch(r"([\w-]+/\d{4}/[\w-]+/[\w-]+)(@[\w:.-]+)?(#[\w.-]+)?", c)
    if m:
        path, version, frag = m.groups()
        expr = f"{path}{version}" if version else expression_for(con, path, "enacted")
        return {"id": f"{expr}{frag or ''}"}
    m = re.search(r"(?:^|\b)(?:s\.?|section|art\.?|artigo)\s*"
                  r"(\d+)(?:\.?º)?(?:\s*-\s*([A-Za-z]))?"
                  r"\s+(?:of\s+(?:the\s+)?|d[oa]\s+)?(.+)", c, re.IGNORECASE)
    if m:
        sec = m.group(1) + (f"-{m.group(2).upper()}" if m.group(2) else "")
        name = m.group(3).strip()
    else:
        sec, name = None, c
    ym = re.search(r"(\d{4})\s*$", name)
    year = int(ym.group(1)) if ym else None
    name_key = re.sub(r"\d{4}\s*$", "", name).strip().upper()
    for work_id, title, wyear, aliases in con.execute(
            "SELECT id, title, year, aliases FROM works"):
        if year and wyear != year:
            continue
        candidates = [a.strip().upper() for a in (aliases or "").split(",") if a.strip()]
        if name_key and name_key not in title.upper() \
                and name_key != acronym(title) and name_key not in candidates:
            continue
        expr = expression_for(con, work_id, "enacted")
        return {"id": _fragment_id(con, expr, sec) if sec else expr}
    raise DonnaError(f"cannot resolve {citation!r}")

# ---------------------------------------------------------------- read verbs

def get_fragment(con, fid):
    row = con.execute("SELECT id, heading, text, content_hash, expression_id"
                      " FROM fragments WHERE id = ?", (fid,)).fetchone()
    if not row:
        raise DonnaError(f"unknown fragment {fid!r} (is the Work ingested?)")
    return row

def q_text(con, ident):
    if "#" in ident:
        _, heading, text, _, _ = get_fragment(con, ident)
        return {"id": ident, "heading": heading, "text": text}
    rows = con.execute("SELECT id, heading, text FROM fragments WHERE"
                       " expression_id = ? ORDER BY ord", (ident,)).fetchall()
    if not rows:
        raise DonnaError(f"unknown expression {ident!r}")
    return {"id": ident, "fragments": [{"id": i, "heading": h, "text": t}
                                       for i, h, t in rows]}

def q_status(con, ident):
    expr_id = ident.split("#")[0]
    expr = con.execute("SELECT e.id, w.title, e.source_url, e.content_hash,"
                       " e.ingested_at FROM expressions e JOIN works w"
                       " ON w.id = e.work_id WHERE e.id = ?", (expr_id,)).fetchone()
    if not expr:
        raise DonnaError(f"unknown expression {expr_id!r}")
    out = {"expression": {"id": expr[0], "title": expr[1], "source_url": expr[2],
                          "content_hash": expr[3], "ingested_at": expr[4]}}
    if "#" in ident:
        frag = get_fragment(con, ident)
        out["fragment"] = {"id": frag[0], "content_hash": frag[3]}
    att = con.execute("SELECT fetched_at, raw_sha256, parser, checks_json FROM"
                      " attestations WHERE expression_id = ? ORDER BY id DESC",
                      (expr_id,)).fetchone()
    if att:
        out["attestation"] = {"fetched_at": att[0], "raw_sha256": att[1],
                              "parser": att[2], "checks": json.loads(att[3])}
    return out

def q_versions(con, work_path):
    rows = con.execute("SELECT id, content_hash, ingested_at, source_url FROM"
                       " expressions WHERE work_id = ? ORDER BY version",
                       (work_path,)).fetchall()
    if not rows:
        raise DonnaError(f"no expressions ingested for {work_path!r}")
    return {"work": work_path,
            "expressions": [{"id": i, "content_hash": h, "ingested_at": at,
                             "source_url": u} for i, h, at, u in rows]}

def q_quote(con, fid, text):
    _, _, body, _, _ = get_fragment(con, fid)
    needle, hay = quote_normal(text), quote_normal(body)
    if needle in hay:
        return {"verified": True, "fragment": fid}
    words = hay.split()
    n = max(len(needle.split()), 4)
    windows = [" ".join(words[i:i + n]) for i in range(0, max(len(words) - n + 1, 1))]
    best = difflib.get_close_matches(needle, windows, n=1, cutoff=0)
    out = {"verified": False, "fragment": fid}
    if best:
        out["nearest"] = best[0][:300]
    return out

def q_search(con, query):
    if HAS_FTS:
        rows = con.execute("SELECT id, heading, snippet(fragments_fts, 2, '[', ']',"
                           " '…', 12) FROM fragments_fts WHERE fragments_fts MATCH ?"
                           " ORDER BY rank LIMIT 10", (query,)).fetchall()
    else:
        rows = con.execute("SELECT id, heading, substr(text, 1, 80) FROM fragments"
                           " WHERE text LIKE ? LIMIT 10", (f"%{query}%",)).fetchall()
    return {"query": query,
            "results": [{"id": i, "heading": h, "snippet": s} for i, h, s in rows]}

def q_diff(con, a, b):
    fa, fb = get_fragment(con, a), get_fragment(con, b)
    out = list(difflib.unified_diff(fa[2].splitlines(), fb[2].splitlines(),
                                    fromfile=a, tofile=b, lineterm=""))
    return {"a": a, "b": b, "identical": not out, "diff": "\n".join(out)}

def q_verify(con, expr_id):
    expr = con.execute("SELECT content_hash FROM expressions WHERE id = ?",
                       (expr_id,)).fetchone()
    if not expr:
        raise DonnaError(f"unknown expression {expr_id!r}")
    rows = con.execute("SELECT id, text, content_hash FROM fragments WHERE"
                       " expression_id = ? ORDER BY ord", (expr_id,)).fetchall()
    mismatches = [fid for fid, text, h in rows if sha256(text) != h]
    expr_ok = sha256("\n".join(h for _, _, h in rows)) == expr[0]
    att_row = con.execute("SELECT payload_json, signature, signer FROM attestations"
                          " WHERE expression_id = ? ORDER BY id DESC",
                          (expr_id,)).fetchone()
    att = {"present": bool(att_row), "signed": False}
    if att_row and att_row[0]:
        att["payload_matches_corpus"] = \
            json.loads(att_row[0]).get("content_hash") == expr[0]
        if att_row[1]:
            ok, detail = verify_signature(att_row[0].encode(), att_row[1], att_row[2])
            att.update(signed=True, signature_ok=ok, detail=detail)
    ok = (not mismatches and expr_ok
          and att.get("payload_matches_corpus", True)
          and att.get("signature_ok", True))
    return {"expression": expr_id, "ok": ok, "fragments_checked": len(rows),
            "fragment_mismatches": mismatches, "expression_hash_ok": expr_ok,
            "attestation": att}

# ---------------------------------------------------------------- mcp server

MCP_VERSION = "donna/0.4.0"
_S = lambda name, desc: {"type": "object", "required": [name],
                         "properties": {name: {"type": "string", "description": desc}}}
MCP_TOOLS = [
    {"name": "donna_resolve",
     "description": "Resolve a legal citation (human form like 's 42 DPA 2018' or"
                    " 'art. 66.º CIRC', an ELI URL, or an id path) to a canonical"
                    " fragment/expression id.",
     "inputSchema": _S("citation", "the citation to resolve")},
    {"name": "donna_text",
     "description": "Canonical text of a fragment id (or all fragments of an"
                    " expression id).",
     "inputSchema": _S("id", "fragment or expression id")},
    {"name": "donna_status",
     "description": "Provenance for an id: source URL, content hashes, ingestion"
                    " attestation and structure-check results.",
     "inputSchema": _S("id", "fragment or expression id")},
    {"name": "donna_versions",
     "description": "List every ingested Expression (version) of a Work.",
     "inputSchema": _S("work", "work path, e.g. ie/2018/act/7")},
    {"name": "donna_quote",
     "description": "Verify that a quote appears verbatim (typographic tolerance"
                    " only) in a fragment. Returns verified true/false and, when"
                    " false, the nearest actual text. THE claim-verification"
                    " primitive: run it on every legal quotation before relying"
                    " on it.",
     "inputSchema": {"type": "object", "required": ["id", "text"],
                     "properties": {"id": {"type": "string",
                                           "description": "fragment id"},
                                    "text": {"type": "string",
                                             "description": "the quoted text"}}}},
    {"name": "donna_search",
     "description": "Lexical full-text search over ingested fragments.",
     "inputSchema": _S("query", "search terms")},
    {"name": "donna_verify",
     "description": "Recompute every fragment hash and the expression hash for"
                    " an Expression, compare against the stored corpus, and"
                    " check the ingestion attestation's sshsig signature.",
     "inputSchema": _S("expression", "expression id to verify")},
    {"name": "donna_diff",
     "description": "Unified diff of two fragments' canonical text (e.g. the same"
                    " section across enacted and revised Expressions).",
     "inputSchema": {"type": "object", "required": ["a", "b"],
                     "properties": {"a": {"type": "string"},
                                    "b": {"type": "string"}}}},
]

def _mcp_dispatch(con, name, args):
    if name == "donna_resolve":
        return q_resolve(con, args["citation"])
    if name == "donna_text":
        return q_text(con, args["id"])
    if name == "donna_status":
        return q_status(con, args["id"])
    if name == "donna_versions":
        return q_versions(con, args["work"])
    if name == "donna_quote":
        return q_quote(con, args["id"], args["text"])
    if name == "donna_search":
        return q_search(con, args["query"])
    if name == "donna_diff":
        return q_diff(con, args["a"], args["b"])
    if name == "donna_verify":
        return q_verify(con, args["expression"])
    raise DonnaError(f"unknown tool {name!r}")

def cmd_mcp(con):
    def send(payload):
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid, method = msg.get("id"), msg.get("method")
        params = msg.get("params") or {}
        if method == "initialize":
            send({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": params.get("protocolVersion", "2025-03-26"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "donna", "version": MCP_VERSION}}})
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": mid, "result": {"tools": MCP_TOOLS}})
        elif method == "tools/call":
            try:
                data = _mcp_dispatch(con, params.get("name", ""),
                                     params.get("arguments") or {})
                result = {"content": [{"type": "text",
                                       "text": json.dumps(data, ensure_ascii=False)}],
                          "isError": False}
            except (DonnaError, KeyError) as e:
                result = {"content": [{"type": "text", "text": str(e)}],
                          "isError": True}
            send({"jsonrpc": "2.0", "id": mid, "result": result})
        elif method == "ping":
            send({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif mid is not None:
            send({"jsonrpc": "2.0", "id": mid,
                  "error": {"code": -32601, "message": f"method not found: {method}"}})

# ---------------------------------------------------------------- cli

def _print_status(out):
    e = out["expression"]
    print(f"expression: {e['id']}\ntitle:      {e['title']}\nsource:     {e['source_url']}")
    print(f"expr_hash:  {e['content_hash']}\ningested:   {e['ingested_at']}")
    if "fragment" in out:
        print(f"fragment:   {out['fragment']['id']}\nfrag_hash:  {out['fragment']['content_hash']}")
    if "attestation" in out:
        a = out["attestation"]
        print(f"attested:   {a['fetched_at']}  parser {a['parser']}\nraw_sha256: {a['raw_sha256']}")
        print(f"checks:     {json.dumps(a['checks'], ensure_ascii=False)}")

def _print_text(out):
    frags = out.get("fragments") or [out]
    for f in frags:
        if f.get("heading"):
            print(f["heading"])
        print(f["text"])
        if len(frags) > 1:
            print()

def main():
    ap = argparse.ArgumentParser(prog="donna", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="donna.db")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON on stdout")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ingest").add_argument("work")
    sub.add_parser("resolve").add_argument("citation")
    sub.add_parser("versions").add_argument("work")
    sub.add_parser("text").add_argument("id")
    sub.add_parser("status").add_argument("id")
    q = sub.add_parser("quote"); q.add_argument("id"); q.add_argument("text")
    sub.add_parser("search").add_argument("query")
    d = sub.add_parser("diff"); d.add_argument("a"); d.add_argument("b")
    sub.add_parser("mcp")
    sub.add_parser("keygen")
    sub.add_parser("verify").add_argument("expression")
    args = ap.parse_args()
    global KEY_DIR
    KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(args.db)), ".donna")
    if args.cmd == "keygen":
        key, _ = _key_paths()
        if os.path.exists(key):
            print(f"key already exists at {key}", file=sys.stderr)
            sys.exit(1)
        os.makedirs(KEY_DIR, exist_ok=True)
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key, "-N", "",
                        "-C", "donna-ingester", "-q"], check=True)
        print(f"ingester key created: {key}")
        return
    con = db_open(args.db)
    if args.cmd == "ingest":
        ingest(con, args.work)
        return
    if args.cmd == "mcp":
        cmd_mcp(con)
        return
    try:
        if args.cmd == "resolve":
            out = q_resolve(con, args.citation)
        elif args.cmd == "versions":
            out = q_versions(con, args.work)
        elif args.cmd == "text":
            out = q_text(con, args.id)
        elif args.cmd == "status":
            out = q_status(con, args.id)
        elif args.cmd == "quote":
            out = q_quote(con, args.id, args.text)
        elif args.cmd == "search":
            out = q_search(con, args.query)
        elif args.cmd == "diff":
            out = q_diff(con, args.a, args.b)
        elif args.cmd == "verify":
            out = q_verify(con, args.expression)
    except DonnaError as e:
        if args.json:
            print(json.dumps({"error": str(e)}, ensure_ascii=False))
        else:
            print(e, file=sys.stderr)
        sys.exit(1)
    if args.json:
        print(json.dumps(out, ensure_ascii=False))
        if args.cmd == "quote" and not out["verified"]:
            sys.exit(1)
        if args.cmd == "search" and not out["results"]:
            sys.exit(1)
        if args.cmd == "verify" and not out["ok"]:
            sys.exit(1)
        return
    if args.cmd == "resolve":
        print(out["id"])
    elif args.cmd == "versions":
        for e in out["expressions"]:
            print(f"{e['id']}\n  hash {e['content_hash'][:16]}…  ingested"
                  f" {e['ingested_at']}\n  {e['source_url']}")
    elif args.cmd == "text":
        _print_text(out)
    elif args.cmd == "status":
        _print_status(out)
    elif args.cmd == "quote":
        if out["verified"]:
            print(f"VERIFIED: quote appears verbatim in {out['fragment']}")
        else:
            print(f"NOT VERIFIED: quote not found in {out['fragment']}",
                  file=sys.stderr)
            if out.get("nearest"):
                print(f"nearest text: {out['nearest']}", file=sys.stderr)
            sys.exit(1)
    elif args.cmd == "search":
        for r in out["results"]:
            print(f"{r['id']}\n  {r['heading']}\n  {r['snippet']}")
        if not out["results"]:
            sys.exit("no matches")
    elif args.cmd == "diff":
        print(out["diff"] or "identical")
    elif args.cmd == "verify":
        a = out["attestation"]
        state = ("signature ok" if a.get("signature_ok")
                 else "signed, SIGNATURE FAILED" if a.get("signed")
                 else "unsigned")
        print(f"{out['expression']}\n  fragments: {out['fragments_checked']}"
              f" checked, {len(out['fragment_mismatches'])} mismatched\n"
              f"  expression hash: {'ok' if out['expression_hash_ok'] else 'MISMATCH'}\n"
              f"  attestation: {state}")
        if out["fragment_mismatches"]:
            print("  mismatched: " + ", ".join(out["fragment_mismatches"]))
        if not out["ok"]:
            sys.exit(1)

if __name__ == "__main__":
    main()
