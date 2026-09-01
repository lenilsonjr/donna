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
KIND_PREFIX = {"section": "sec", "schedule": "sched", "article": "art",
               "annex": "anexo"}

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

class DonnaError(Exception):
    """Verb-level failure surfaced as exit 1 on the CLI, isError over MCP."""

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

BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
              " AppleWebKit/537.36 (KHTML, like Gecko)"
              " Chrome/128.0.0.0 Safari/537.36")

def fetch(url, ua=None):
    req = urllib.request.Request(url, headers={"User-Agent": ua or UA})
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

def pt_at_acquire(cfg, version):
    if version != "consolidated":
        raise DonnaError("this source serves @consolidated only")
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

# ---------------------------------------------------------------- PGDL adapter

PGDL_PARSER = "donna-pgdl/0.5.0"
PGDL_URL = ("https://www.pgdlisboa.pt/leis/lei_mostra_articulado.php"
            "?nid={nid}&tabela=leis&ficha=1&pagina={p}")
PGDL_HEADER = re.compile(
    r'<td class=txt_base_b_l[^>]*>.{0,200}?'
    r'(?:Artigo\s+(\d+)\.º(?:-([A-Z]+))?'
    r'|(TABELA\s+[IVX]+(?:-[A-Z])?|ANEXO(?:\s+[IVX]+)?))'
    r'\s*(?:<br>\s*([^<]*))?</td>', re.S)

def _pgdl_clean(chunk, counts):
    chunk = re.sub(r'<td class=txt_11_b_l.*?</td>',
                   lambda m: counts.__setitem__("struct", counts["struct"] + 1) or "",
                   chunk, flags=re.S)
    chunk = re.sub(r'<(?:script|select|style).*?</(?:script|select|style)>', "",
                   chunk, flags=re.S | re.I)
    chunk = re.sub(r'<br\s*/?>', "\n", chunk, flags=re.I)
    chunk = re.sub(r'</td>|</tr>|</p>', "\n", chunk, flags=re.I)
    chunk = re.sub(r'<[^>]+>', "", chunk)
    return canonical(html.unescape(chunk))

def pgdl_acquire(cfg, version):
    if version != "consolidated":
        raise DonnaError("this source serves @consolidated only")
    raws, pages = [], []
    raw = fetch(PGDL_URL.format(nid=cfg["nid"], p=1))
    raws.append(raw)
    pages.append(raw.decode("iso-8859-1", errors="replace"))
    # follow the site's own pager hrefs (ficha=, not pagina=, drives the offset)
    pager, seen_p = [], set()
    for m in re.finditer(r"href='(lei_mostra_articulado\.php\?[^']*nid=%s[^']*)'"
                         % cfg["nid"], pages[0]):
        href = m.group(1)
        pm = re.search(r"pagina=(\d+)", href)
        if pm and int(pm.group(1)) > 1 and pm.group(1) not in seen_p:
            seen_p.add(pm.group(1))
            pager.append((int(pm.group(1)), href))
    for _, href in sorted(pager):
        time.sleep(0.3)
        raw = fetch("https://www.pgdlisboa.pt/leis/" + html.unescape(href))
        raws.append(raw)
        pages.append(raw.decode("iso-8859-1", errors="replace"))
    expected = []
    for m in re.finditer(r'<option value="%sA\d+">Artigo\s+(\d+)\.º(?:-([A-Z]+))?'
                         % cfg["nid"], pages[0]):
        n = m.group(1) + (f"-{m.group(2)}" if m.group(2) else "")
        if n not in expected:
            expected.append(n)
    counts = {"struct": 0}
    fragments, seen = [], set()
    for page in pages:
        heads = list(PGDL_HEADER.finditer(page))
        for i, m in enumerate(heads):
            if m.group(3):  # annex/table header
                kind = "annex"
                number = re.sub(r"\s+", "-", m.group(3).strip().lower())
                heading = m.group(3).strip()
            else:
                kind = "article"
                number = m.group(1) + (f"-{m.group(2)}" if m.group(2) else "")
                heading = html.unescape((m.group(4) or "").strip())
            if number in seen:
                continue
            seen.add(number)
            end = heads[i + 1].start() if i + 1 < len(heads) else len(page)
            body = _pgdl_clean(page[m.end():end], counts)
            # PGDL appends an amendment-history footer to each article
            cut = re.search(r"Contém as alterações|Consultar versões anteriores"
                            r"|Consultar esta disposição", body)
            if cut:
                body = canonical(body[:cut.start()])
                counts["hist"] = counts.get("hist", 0) + 1
            fragments.append({"kind": kind, "number": number,
                              "heading": heading, "text": body})
    missing = [n for n in expected if n not in seen]
    arts = [f for f in fragments if f["kind"] == "article"]
    seq = sorted({int(re.match(r"\d+", f["number"]).group(0)) for f in arts})
    checks = {"tier": "B", "articles": len(arts),
              "annexes": len(fragments) - len(arts),
              "pages_fetched": len(pages),
              "toc_expected": len(expected), "toc_missing": missing,
              "numbering_gaps": numbering_gaps(seq),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]],
              "structure_cells_stripped": counts["struct"],
              "history_footers_stripped": counts.get("hist", 0)}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "pt",
            "source_url": PGDL_URL.format(nid=cfg["nid"], p=1),
            "raw": b"".join(raws), "checks": checks, "parser": PGDL_PARSER}

# ---------------------------------------------------------------- Planalto adapter

BR_PARSER = "donna-planalto/0.2.0"
BR_EDITORIAL = re.compile(
    r"\(\s*(?:Redação dada|Incluíd[oa]|Acrescid[oa]|Renumerad[oa]|Vide|"
    r"Regulamento|Vigência|Produção de efeito)[^)]*\)", re.I)

def planalto_acquire(cfg, version):
    if version != "consolidated":
        raise DonnaError("this source serves @consolidated only")
    # planalto.gov.br resets connections from non-browser user agents
    raw = fetch(cfg["url"], ua=BROWSER_UA)
    page = raw.decode("windows-1252", errors="replace")
    counts = {"strike": len(re.findall(r"<strike", page, re.I))}
    page = re.sub(r"<strike.*?</strike>", "", page, flags=re.S | re.I)
    page = re.sub(r"<(?:script|style).*?</(?:script|style)>", "", page,
                  flags=re.S | re.I)
    page = re.sub(r"</p>|<br\s*/?>", "\n", page, flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", "", page))
    counts["editorial"] = len(BR_EDITORIAL.findall(text))
    text = BR_EDITORIAL.sub("", text)
    text = canonical(text)
    # cut the signature block after the last article
    sig = re.search(r"(?m)^Brasília,\s", text)
    art_re = re.compile(r"(?m)^\s*Art\.?\s*(\d+)(?:º|o)?(?:-([A-Z]))?[\s.]")
    heads = [m for m in art_re.finditer(text) if not sig or m.start() < sig.start()]
    if not heads:
        raise DonnaError("no articles found — page layout may have changed")
    # laws quote other laws' articles inline; keep the longest nondecreasing
    # chain of article numbers so out-of-place quoted headers fall out
    keys = [(int(m.group(1)), ord(m.group(2)) if m.group(2) else 0) for m in heads]
    best_len, prev = [1] * len(keys), [-1] * len(keys)
    for i in range(len(keys)):
        for j in range(i):
            if keys[j] <= keys[i] and best_len[j] + 1 > best_len[i]:
                best_len[i], prev[i] = best_len[j] + 1, j
    i = max(range(len(keys)), key=lambda k: best_len[k])
    chain = []
    while i != -1:
        chain.append(i)
        i = prev[i]
    chain.reverse()
    quoted_skipped = len(heads) - len(chain)
    picked = [heads[i] for i in chain]
    fragments, seen = [], set()
    for i, m in enumerate(picked):
        number = m.group(1) + (f"-{m.group(2)}" if m.group(2) else "")
        if number in seen:
            continue
        seen.add(number)
        end = picked[i + 1].start() if i + 1 < len(picked) else \
            (sig.start() if sig else len(text))
        fragments.append({"kind": "article", "number": number, "heading": "",
                          "text": canonical(text[m.start():end])})
    seq = sorted({int(re.match(r"\d+", f["number"]).group(0)) for f in fragments})
    checks = {"tier": "B", "articles": len(fragments),
              "numbering_gaps": numbering_gaps(seq),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]],
              "quoted_headers_skipped": quoted_skipped,
              "struck_blocks_stripped": counts["strike"],
              "editorial_notes_stripped": counts["editorial"]}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "pt-BR",
            "source_url": cfg["url"], "raw": raw,
            "checks": checks, "parser": BR_PARSER}

# ---------------------------------------------------------------- GovInfo adapter

GI_PARSER = "donna-govinfo/0.2.0"

def govinfo_acquire(cfg, version):
    if version != "consolidated":
        raise DonnaError("this source serves @consolidated only")
    key = os.environ.get("GOVINFO_API_KEY", "DEMO_KEY")
    url = f"https://api.govinfo.gov/packages/{cfg['package']}/htm?api_key={key}"
    raw = fetch(url, ua=BROWSER_UA)
    page = raw.decode("utf-8", errors="replace")
    parts = re.split(
        r'<h3 class="section-head">\s*((?:§|&sect;|&#167;)[^<]+?)\s*</h3>', page)
    if len(parts) < 3:
        raise DonnaError("no section-head elements — page layout may have changed")
    cut_re = re.compile(r'class="(?:source-credit|note-head|note-body)')
    fragments, seen, notes_cut = [], set(), 0
    for hdr, body in zip(parts[1::2], parts[2::2]):
        hdr = hdr.replace("&sect;", "§").replace("&#167;", "§")
        m = re.match(r"§+\s*([0-9A-Za-z]+(?:-[0-9A-Za-z]+)?)[.,\s]*(.*)", hdr)
        if not m:
            continue
        number, heading = m.group(1), html.unescape(m.group(2)).strip().rstrip("]")
        if number in seen:
            continue
        seen.add(number)
        cut = cut_re.search(body)
        if cut:
            notes_cut += 1
            body = body[:cut.start()]
        body = re.sub(r"</p>|</h4>|</tr>", "\n", body, flags=re.I)
        body = re.sub(r"<[^>]+>", "", body)
        fragments.append({"kind": "section", "number": number, "heading": heading,
                          "text": canonical(html.unescape(body))})
    checks = {"tier": "B", "sections": len(fragments),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]],
              "note_blocks_cut": notes_cut}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "en",
            "source_url": url.replace(key, "<api_key>"), "raw": raw,
            "checks": checks, "parser": GI_PARSER}

# ---------------------------------------------------------------- Wyoming adapter

WY_PARSER = "donna-wy-pdf/0.2.0"
WY_BASE = "https://wyoleg.gov/statutes/compress/"

def wy_pdf_acquire(cfg, version):
    if version != "consolidated":
        raise DonnaError("this source serves @consolidated only")
    import shutil
    if not shutil.which("pdftotext"):
        raise DonnaError("pdftotext not found — Tier C extraction needs poppler"
                         " (brew install poppler)")
    raw = fetch(WY_BASE + cfg["file"], ua=BROWSER_UA)
    with tempfile.TemporaryDirectory() as td:
        pdf = os.path.join(td, "t.pdf")
        with open(pdf, "wb") as fh:
            fh.write(raw)
        r = subprocess.run(["pdftotext", "-enc", "UTF-8", pdf, "-"],
                           capture_output=True, check=True)
    text = r.stdout.decode("utf-8", errors="replace").replace("\f", "\n")
    tnum = cfg["ws_title"]
    head_re = re.compile(r"^(%s-\d+(?:\.\d+)?-\d+)\.(?:\s+(\S.*))?$"
                         % re.escape(tnum), re.M)
    def key(number):
        parts = number.split("-")
        return tuple(float(x) if "." in x else int(x) for x in parts[1:])
    heads = list(head_re.finditer(text))
    picked, last = [], None
    for m in heads:  # monotonic filter: wrapped cross-references start lines too
        k = key(m.group(1))
        if last is None or k >= last:
            picked.append(m)
            last = k
    fragments, seen = [], set()
    for i, m in enumerate(picked):
        number = m.group(1)
        if number in seen:
            continue
        seen.add(number)
        end = picked[i + 1].start() if i + 1 < len(picked) else len(text)
        chunk = text[m.end():end]
        lines = [l for l in chunk.splitlines()]
        heading = (m.group(2) or "").strip()
        if not heading:
            for j, l in enumerate(lines):
                if l.strip():
                    heading = l.strip()
                    lines = lines[j + 1:]
                    break
        body = canonical("\n".join(lines))
        if not body:  # repealed sections carry only their status line
            body = heading
        fragments.append({"kind": "section", "number": number,
                          "heading": heading.rstrip("."), "text": body})
    chapters = {f["number"].split("-")[1] for f in fragments}
    checks = {"tier": "C", "extractor": "pdftotext",
              "sections": len(fragments), "chapters": len(chapters),
              "headers_rejected": len(heads) - len(picked),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]]}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "en",
            "source_url": WY_BASE + cfg["file"], "raw": raw,
            "checks": checks, "parser": WY_PARSER}

# ---------------------------------------------------------------- work registry

ADAPTERS = {"ie": ie_acquire}  # pattern adapters: any Work in the jurisdiction

WORKS = {
    ("pt", "1988", "dec-lei", "442-b"): {
        "source": pt_at_acquire,
        "title": "Código do Imposto sobre o Rendimento das Pessoas Coletivas"
                 " (Código do IRC)",
        "aliases": "CIRC,CODIGO DO IRC,CÓDIGO DO IRC",
        "index": PT_BASE + "/pt/informacao_fiscal/codigos_tributarios/CIRC_2R"
                 "/Pages/circ-codigo-do-irc-indice.aspx",
        "slug": "irc",
    },
    ("pt", "1994", "dec-lei", "114"): {
        "source": pgdl_acquire, "nid": "349",
        "title": "Código da Estrada (DL n.º 114/94)",
        "aliases": "CE,CODIGO DA ESTRADA,CÓDIGO DA ESTRADA",
    },
    ("pt", "2006", "lei", "5"): {
        "source": pgdl_acquire, "nid": "692",
        "title": "Regime Jurídico das Armas e Munições (Lei n.º 5/2006)",
        "aliases": "LEI DAS ARMAS,RJAM,LEI 5/2006",
    },
    ("pt", "1993", "dec-lei", "15"): {
        "source": pgdl_acquire, "nid": "181",
        "title": "Legislação de Combate à Droga (DL n.º 15/93)",
        "aliases": "LEI DA DROGA,DL 15/93",
    },
    ("pt", "2000", "lei", "30"): {
        "source": pgdl_acquire, "nid": "186",
        "title": "Regime Jurídico do Consumo de Estupefacientes (Lei n.º 30/2000)",
        "aliases": "LEI 30/2000,DESCRIMINALIZACAO,DESCRIMINALIZAÇÃO",
    },
    ("pt", "2008", "lei", "53"): {
        "source": pgdl_acquire, "nid": "1012",
        "title": "Lei de Segurança Interna (Lei n.º 53/2008)",
        "aliases": "LSI,LEI DE SEGURANCA INTERNA,LEI DE SEGURANÇA INTERNA",
    },
    ("pt", "1982", "dec-lei", "400"): {
        "source": pgdl_acquire, "nid": "109",
        "title": "Código Penal (DL n.º 400/82)",
        "aliases": "CP,CODIGO PENAL,CÓDIGO PENAL",
    },
    ("pt", "1987", "dec-lei", "78"): {
        "source": pgdl_acquire, "nid": "199",
        "title": "Código de Processo Penal (DL n.º 78/87)",
        "aliases": "CPP,CODIGO DE PROCESSO PENAL,CÓDIGO DE PROCESSO PENAL",
    },
    ("wy", "1977", "title", "17"): {
        "source": wy_pdf_acquire, "file": "title17.pdf", "ws_title": "17",
        "title": "Wyoming Statutes Title 17 - Corporations, Partnerships and"
                 " Associations (incl. ch. 29, Wyoming LLC Act)",
        "aliases": "WYOMING LLC ACT,WY TITLE 17,WS TITLE 17",
    },
    ("wy", "1977", "title", "34-1"): {
        "source": wy_pdf_acquire, "file": "title34.1.pdf", "ws_title": "34.1",
        "title": "Wyoming Statutes Title 34.1 - Uniform Commercial Code",
        "aliases": "WYOMING UCC,UCC,WY TITLE 34.1",
    },
    ("us", "1986", "usc", "26"): {
        "source": govinfo_acquire, "package": "USCODE-2023-title26",
        "title": "Internal Revenue Code - 26 U.S.C. (2023 edition, GovInfo)",
        "aliases": "IRC,26 USC,INTERNAL REVENUE CODE,US TAX CODE",
    },
    ("br", "1965", "lei", "4737"): {
        "source": planalto_acquire,
        "url": "https://www.planalto.gov.br/ccivil_03/leis/l4737compilado.htm",
        "title": "Código Eleitoral - Lei n.º 4.737/1965",
        "aliases": "CODIGO ELEITORAL,CÓDIGO ELEITORAL,LEI 4737,LEI 4.737",
    },
    ("br", "1997", "lei", "9504"): {
        "source": planalto_acquire,
        "url": "https://www.planalto.gov.br/ccivil_03/leis/l9504.htm",
        "title": "Lei das Eleições - Lei n.º 9.504/1997",
        "aliases": "LEI DAS ELEICOES,LEI DAS ELEIÇÕES,LEI 9504,LEI 9.504",
    },
    ("br", "1995", "lei", "9096"): {
        "source": planalto_acquire,
        "url": "https://www.planalto.gov.br/ccivil_03/leis/l9096.htm",
        "title": "Lei dos Partidos Políticos - Lei n.º 9.096/1995",
        "aliases": "LEI DOS PARTIDOS,LEI 9096,LEI 9.096",
    },
    ("pt", "2018", "lei", "33"): {
        "source": pgdl_acquire, "nid": "2918",
        "title": "Lei da Canábis para Fins Medicinais (Lei n.º 33/2018)",
        "aliases": "LEI DA CANABIS,LEI DA CANÁBIS,CANNABIS MEDICINAL,"
                   "CANABIS MEDICINAL",
    },
    ("pt", "2019", "dec-lei", "8"): {
        "source": pgdl_acquire, "nid": "2997",
        "title": "Utilização de Medicamentos e Substâncias à Base da Planta"
                 " de Canábis (DL n.º 8/2019)",
        "aliases": "DL 8/2019,REGULAMENTO DA CANABIS",
    },
    ("pt", "1986", "lei", "44"): {
        "source": pgdl_acquire, "nid": "1712",
        "title": "Regime do Estado de Sítio e do Estado de Emergência"
                 " (Lei n.º 44/86)",
        "aliases": "ESTADO DE EMERGENCIA,ESTADO DE EMERGÊNCIA,ESTADO DE SITIO",
    },
}

# ---------------------------------------------------------------- ingest

def _acquire(work_path):
    m = re.fullmatch(r"([\w-]+)/(\d{4})/([\w-]+)/([\w-]+)"
                     r"(?:@(enacted|revised|consolidated))?", work_path)
    if not m:
        raise DonnaError(f"work path must look like ie/2018/act/7[@revised],"
                         f" got {work_path!r}")
    jur, year, wtype, num, version = m.groups()
    work_id = f"{jur}/{year}/{wtype}/{num}"
    cfg = WORKS.get((jur, year, wtype, num))
    if cfg:
        version = version or "consolidated"
        return work_id, version, cfg["source"](cfg, version)
    adapter = ADAPTERS.get(jur)
    if not adapter:
        known = ", ".join("/".join(k) for k in WORKS)
        raise DonnaError(f"no adapter for jurisdiction {jur!r} and no configured"
                         f" work {work_id!r} (configured: {known})")
    version = version or "enacted"
    return work_id, version, adapter(year, wtype, num, version)

def _expression_hashes(fragments):
    frag_hashes = [sha256(f["text"]) for f in fragments]
    return frag_hashes, sha256("\n".join(frag_hashes))

def ingest(con, work_path):
    try:
        work_id, version, res = _acquire(work_path)
    except DonnaError as e:
        sys.exit(str(e))
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    expr_id = f"{work_id}@{res['label']}:{res['lang']}"
    frag_hashes, expr_hash = _expression_hashes(res["fragments"])
    frag_rows = []
    for i, (f, h) in enumerate(zip(res["fragments"], frag_hashes)):
        fid = f"{expr_id}#{KIND_PREFIX[f['kind']]}-{f['number']}"
        frag_rows.append((fid, expr_id, f["kind"], f["number"], f["heading"],
                          f["text"], i, h))

    with con:
        jur, year, wtype, num = work_id.split("/")
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
    m = re.search(r"(?:W\.?S\.?\s*)?\b(\d{1,2}(?:\.\d+)?)-(\d+(?:\.\d+)?-\d+)\b", c)
    if m:
        tnum = m.group(1).replace(".", "-")
        row = con.execute("SELECT id FROM works WHERE jurisdiction = 'wy' AND"
                          " number = ?", (tnum,)).fetchone()
        if row:
            expr = expression_for(con, row[0], "consolidated")
            return {"id": _fragment_id(con, expr, f"{m.group(1)}-{m.group(2)}")}
    m = re.search(r"(?:(\d+)\s*U\.?S\.?C\.?|\bIRC\b)\s*§?\s*"
                  r"(\d+[A-Za-z]*)", c)
    if m:
        title = m.group(1) or "26"
        row = con.execute("SELECT id FROM works WHERE type = 'usc' AND"
                          " number = ?", (title,)).fetchone()
        if row:
            expr = expression_for(con, row[0], "consolidated")
            return {"id": _fragment_id(con, expr, m.group(2))}
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
    name_key = re.sub(r"[/,]?\s*\d{4}\s*$", "", name).strip().upper()
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

def q_check(con, work_path):
    work_id, version, res = _acquire(work_path)
    row = con.execute("SELECT id, content_hash FROM expressions WHERE work_id = ?"
                      " AND version LIKE ? ORDER BY version DESC",
                      (work_id, version + "%")).fetchone()
    if not row:
        raise DonnaError(f"no {version} expression ingested for {work_id!r}"
                         " — nothing to compare against")
    stored_id, stored_hash = row
    _, expr_hash = _expression_hashes(res["fragments"])
    att = con.execute("SELECT raw_sha256 FROM attestations WHERE expression_id = ?"
                      " ORDER BY id DESC", (stored_id,)).fetchone()
    raw_now = sha256(res["raw"])
    new_id = f"{work_id}@{res['label']}:{res['lang']}"
    return {"work": work_id, "expression": stored_id,
            "source_changed": bool(att) and att[0] != raw_now,
            "content_changed": expr_hash != stored_hash,
            "stored_hash": stored_hash, "current_hash": expr_hash,
            "new_expression_id": new_id if new_id != stored_id else None}

def q_refs(con, scope=None):
    """Dangling citations: acts cited by ingested fragments that are not in
    the corpus. Deterministic discovery — the corpus points at its own gaps."""
    PT_TYPES = {"lei": "lei", "decreto-lei": "dec-lei", "portaria": "portaria",
                "lei orgânica": "lei-organica",
                "decreto regulamentar": "dec-regulamentar"}
    pt_re = re.compile(r"(Lei Orgânica|Decreto-Lei|Decreto Regulamentar|Portaria"
                       r"|Lei)\s+n\.?[ºo°]?\s*(\d+(?:-[A-Z])?)/(\d{2,4})")
    br_re = re.compile(r"(Lei|Decreto-Lei|Decreto)\s+n[ºo°.]*\s*([\d.]+)"
                       r"(?:\s*,\s*de[^,.;]*?(\d{4}))?")
    usc_re = re.compile(r"(\d+)\s+U\.S\.C\.")
    known = {tuple(w.split("/")) for (w,) in con.execute("SELECT id FROM works")}
    found = {}
    q = "SELECT f.id, f.text, e.lang, e.work_id FROM fragments f JOIN" \
        " expressions e ON e.id = f.expression_id"
    args = ()
    if scope:
        q += " WHERE f.expression_id LIKE ?"
        args = (scope + "%",)
    for fid, text, lang, work_id in con.execute(q, args):
        jur = work_id.split("/")[0]
        cites = []
        if lang == "pt":
            for t, num, yr in pt_re.findall(text):
                y = int(yr)
                if y < 100:
                    y += 1900 if y > 35 else 2000
                cites.append((jur, str(y), PT_TYPES[t.lower()], num.lower()))
        elif lang == "pt-BR":
            for t, num, yr in br_re.findall(text):
                num = num.replace(".", "").strip()
                if not num or not yr:
                    continue
                cites.append((jur, yr, "lei" if t == "Lei" else "dec-lei", num))
        elif lang == "en":
            for title in usc_re.findall(text):
                cites.append(("us", "1986", "usc", title))
        for c in cites:
            if c in known or c[:1] + c[2:] in {k[:1] + k[2:] for k in known}:
                continue
            entry = found.setdefault(c, {"citations": 0, "sample": fid})
            entry["citations"] += 1
    ranked = sorted(found.items(), key=lambda kv: -kv[1]["citations"])
    return {"scope": scope or "corpus",
            "missing": [{"work": "/".join(k), "citations": v["citations"],
                         "sample_source": v["sample"]}
                        for k, v in ranked[:25]]}

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
    {"name": "donna_refs",
     "description": "Discovery: acts cited by the ingested corpus that are not"
                    " themselves ingested, ranked by citation count. Optional"
                    " scope prefix narrows to one work/expression.",
     "inputSchema": {"type": "object", "properties":
                     {"scope": {"type": "string"}}}},
    {"name": "donna_check",
     "description": "Re-fetch an Expression's source (network) and report"
                    " whether the law changed: content_changed compares"
                    " recomputed canonical hashes (definitive), source_changed"
                    " compares raw bytes (cosmetic page churn also trips it).",
     "inputSchema": _S("work", "work path, e.g. ie/2018/act/7[@revised]")},
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
    if name == "donna_check":
        return q_check(con, args["work"])
    if name == "donna_refs":
        return q_refs(con, args.get("scope"))
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
    sub.add_parser("check").add_argument("work")
    sub.add_parser("refs").add_argument("scope", nargs="?")
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
        elif args.cmd == "check":
            out = q_check(con, args.work)
        elif args.cmd == "refs":
            out = q_refs(con, args.scope)
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
        if args.cmd == "check" and out["content_changed"]:
            sys.exit(2)
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
    elif args.cmd == "refs":
        for r in out["missing"]:
            print(f"{r['citations']:4}x  {r['work']}\n       e.g. cited in {r['sample_source']}")
        if not out["missing"]:
            print("no dangling citations found")
    elif args.cmd == "check":
        print(f"{out['expression']}")
        print(f"  source bytes:  {'CHANGED' if out['source_changed'] else 'unchanged'}")
        print(f"  content:       {'CHANGED' if out['content_changed'] else 'unchanged'}")
        if out.get("new_expression_id"):
            print(f"  new version:   {out['new_expression_id']} — re-ingest to adopt")
        if out["content_changed"]:
            sys.exit(2)

if __name__ == "__main__":
    main()
