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
CREATE TABLE IF NOT EXISTS derived(
  id INTEGER PRIMARY KEY AUTOINCREMENT, fragment_id TEXT, kind TEXT,
  producer TEXT, source_sha256 TEXT, content TEXT, created_at TEXT);
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
    text = text.replace("\u200b", "").replace("\ufeff", "")
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

def _trusted_signers_path():
    return os.path.join(KEY_DIR, "trusted_signers")

def _ensure_trusted_file():
    """Trust roots live in the filesystem, never in the corpus being verified.
    Bootstraps from the local ingester public key when present."""
    path = _trusted_signers_path()
    if os.path.exists(path):
        return path
    _, pub = _key_paths()
    if os.path.exists(pub):
        os.makedirs(KEY_DIR, exist_ok=True)
        with open(pub) as fh:
            kt_b64 = " ".join(fh.read().split()[:2])
        with open(path, "w") as fh:
            fh.write(f"donna-ingester {kt_b64}\n")
        print(f"trusted_signers bootstrapped from local key: {path}",
              file=sys.stderr)
        return path
    return None

def _sshsig_verify(payload, sig, allowed_line_or_file, is_file=False):
    with tempfile.TemporaryDirectory() as td:
        sigf = os.path.join(td, "payload.sig")
        with open(sigf, "w") as fh:
            fh.write(sig)
        allowed = allowed_line_or_file
        if not is_file:
            allowed = os.path.join(td, "allowed_signers")
            with open(allowed, "w") as fh:
                fh.write(f"donna-ingester {allowed_line_or_file}\n")
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", allowed,
                            "-I", "donna-ingester", "-n", SIG_NAMESPACE,
                            "-s", sigf], input=payload, capture_output=True)
    return r.returncode == 0, (r.stderr or r.stdout).decode().strip()

def verify_signature(payload, sig, signer):
    """-> (signature_ok, trusted, detail). The signature is checked against the
    embedded signer key (payload integrity) and independently against the
    trusted_signers file (provenance authentication)."""
    trusted_file = _ensure_trusted_file()
    if trusted_file:
        ok, detail = _sshsig_verify(payload, sig, trusted_file, is_file=True)
        if ok:
            return True, True, detail
    ok, detail = _sshsig_verify(payload, sig, signer)
    return ok, False, detail

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

PT_PARSER = "donna-pt/0.14.0"
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

PT_ART_LINE = re.compile(r"Artigo\s+(\d+)\.?º?(?:\s*-\s*([A-Za-z]+))?",
                         re.IGNORECASE)
PT_FLAT_CUT = re.compile(r"Links Úteis|Contém as alterações|Consultar versões"
                         r"|Consultar esta disposição|\[\+ info\]"
                         r"|Redações anteriores")
PT_REDACTION = re.compile(r"\((?:Redac?ção|Aditado|Epígrafe|Rectificad|Retificad)"
                          r"[^)]*\)")

def _pt_flat(src_html):
    """Last-resort extraction for page vintages whose heading/body never
    reach p/div blocks: strip to text lines and slice around the Artigo line.
    Loses em-based redaction stripping, so those notes are removed textually."""
    s = re.sub(r"<!--.*?-->", "", src_html, flags=re.S)
    s = re.sub(r"<(?:script|style|select)[^>]*>.*?</(?:script|style|select)>",
               "", s, flags=re.S | re.I)
    s = re.sub(r"<br\s*/?>|</p>|</h\d>|</td>|</tr>|</div>", "\n", s, flags=re.I)
    s = canonical(html.unescape(re.sub(r"<[^>]+>", "", s)))
    lines = s.split("\n")
    art_at = num = None
    for k, l in enumerate(lines):
        m = PT_ART_LINE.match(l)
        if m and (len(l) <= 40 or not re.match(
                r"\s*(?:d[aoe]s?\b|,|;|e\b|n\.º)", l[m.end():])):
            art_at, num = k, m.group(1) + (
                f"-{m.group(2).upper()}" if m.group(2) else "")
            fused = l[m.end():].strip()
            break
    if art_at is None:
        return None, "", 0, None
    body = ([fused] if fused else []) + lines[art_at + 1:]
    for k, l in enumerate(body):
        if PT_FLAT_CUT.search(l):
            body = body[:k]
            break
    red = sum(len(PT_REDACTION.findall(l)) for l in body)
    body = [PT_REDACTION.sub("", l) for l in body]
    heading = ""
    if body and len(body[0]) <= 90 and not re.match(r"\d+\s*[-—.]|[a-z]\)|\(",
                                                    body[0]):
        heading, body = body[0], body[1:]
    return canonical("\n".join(body)), heading, red, num

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
        for i, (h, t, em) in enumerate(blocks):
            if require_center and "atcenteredtext" not in h \
                    and "text-align:center" not in h:
                continue
            lines = [l.strip() for l in t.split("\n")]
            art_at = next((k for k, l in enumerate(lines)
                           if art_re.match(l) and len(l) <= 40), None)
            if art_at is None and lines:
                # heading element fused with body text (h4 vintage):
                # "Artigo 89.º-A a) Considera-se..." — split, unless the tail
                # reads like a mid-sentence citation ("Artigo 63.º da LGT")
                fm = art_re.match(lines[0])
                if fm and len(lines[0]) > 40 and not re.match(
                        r"\s*(?:d[aoe]s?\b|,|;|e\b|n\.º)", lines[0][fm.end():]):
                    lines = [lines[0][:fm.end()],
                             lines[0][fm.end():].strip()] + lines[1:]
                    art_at = 0
            if art_at is None and em:
                # some vintages italicize the heading itself: the em buffer
                # may hold "Artigo 19.º" (suffix "-A" in visible text) or a
                # glued "Secção X Artigo 11.ºHeading" run
                t_first = lines[0] if lines else ""
                for el in em.split("\n"):
                    am = art_re.search(el)
                    if not am:
                        continue
                    sm = re.match(r"-[A-Za-z]+\b", t_first)
                    suffix = sm.group(0) if sm else ""
                    probe = el[am.start():am.end()] + suffix
                    tail = el[am.end():].lstrip(" .-–")
                    remainder = lines[1:] if (suffix or not t_first) else lines
                    remainder = [l for l in remainder if not l.startswith("(")]
                    lines = [probe] + ([tail] if tail else []) + remainder
                    art_at = 0
                    break
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
        fb_body, fb_head, fb_red, fb_num = _pt_flat(html_text)
        if fb_body and fb_num:
            return fb_body, fb_head, parser.em_stripped + fb_red, 0, fb_num
        return None, "", parser.em_stripped, 0, None
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
    if heading and ("\n" in heading or len(heading) > 90):
        # heading glue: some vintages pack epigraph and body into one block
        hl = heading.split("\n")
        keep = hl[0] if len(hl[0]) <= 90 and not body_shape.match(hl[0]) else ""
        spill = hl[1:] if keep else hl
        if spill:
            body = [canonical("\n".join(spill))] + body
        heading = keep
    if heading and body_shape.match(heading):
        # rest-of-block text was statutory body, not an epigraph
        body.insert(0, heading)
        heading = ""
    num = None
    nm = re.match(r"Artigo\s+(\d+)\.?º?(?:\s*-\s*([A-Za-z]+))?",
                  lines[art_at], re.IGNORECASE)
    if nm:
        num = nm.group(1) + (f"-{nm.group(2).upper()}" if nm.group(2) else "")
    out_body = canonical("\n".join(body))
    if not out_body:
        fb_body, fb_head, fb_red, fb_num = _pt_flat(html_text)
        if fb_body:
            return fb_body, heading or fb_head, \
                parser.em_stripped + fb_red, notes, num or fb_num
    return out_body, heading, parser.em_stripped, notes, num

def pt_at_acquire(cfg, version):
    if version != "consolidated":
        raise DonnaError("this source serves @consolidated only")
    index_raw = fetch(cfg["index"])
    index_html = index_raw.decode("utf-8", errors="replace")
    seen, pages = set(), []
    base = re.sub(r"^https?://[^/]+", "", cfg["index"])
    base = re.split(r"/pages/", base, flags=re.IGNORECASE)[0]
    if cfg.get("harvest_all"):
        # heterogeneous link shapes: fetch every page in the index's own
        # directory; article numbers come from the pages themselves
        idx_name = cfg["index"].rsplit("/", 1)[-1].lower()
        for m in re.finditer(r'href="(%s/pages/([^"/]+\.aspx))"'
                             % re.escape(base), index_html, re.IGNORECASE):
            href, leaf = m.group(1), m.group(2).lower()
            if leaf == idx_name or leaf == "default.aspx" or href in seen:
                continue
            seen.add(href)
            pages.append((None, PT_BASE + href if href.startswith("/") else href))
    else:
        for m in re.finditer(r'href="(%s/pages/%s(\d+)([a-z]?)\.aspx)"'
                             % (re.escape(base), cfg["slug"]),
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
    unparsed, nonarticle, have_nums = [], [], set()
    for number, url in pages:
        raw = fetch(url)
        raw_parts.append(raw)
        body, heading, em_n, notes_n, page_num = _pt_extract(
            raw.decode("utf-8", errors="replace"))
        em_total += em_n
        notes_total += notes_n
        if number is None:  # harvest_all: trust the page's own numbering
            if body is None or page_num is None:
                nonarticle.append(url.rsplit("/", 1)[-1])
                time.sleep(0.25)
                continue
            if page_num in have_nums:
                time.sleep(0.25)
                continue
            number = page_num
        elif body is None:
            unparsed.append(number)
            body = ""
        have_nums.add(number)
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
              "nonarticle_pages_skipped": nonarticle,
              "redaction_notes_stripped": em_total,
              "editorial_notes_stripped": notes_total}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "pt",
            "source_url": cfg["index"], "raw": b"".join(raw_parts),
            "checks": checks, "parser": PT_PARSER}

# ---------------------------------------------------------------- PGDL adapter

PGDL_PARSER = "donna-pgdl/0.7.0"
PGDL_URL = ("https://www.pgdlisboa.pt/leis/lei_mostra_articulado.php"
            "?nid={nid}&tabela=leis&ficha=1&pagina={p}")
PGDL_HEADER = re.compile(
    r'<td class=txt_base_b_l[^>]*>.{0,200}?'
    r'(?:(?i:Artigo)\s+(\d+)\.º(?:-([A-Z]+))?(?:\s*\([^<)]{0,80}\))?'
    r'|(TABELA\s+[IVX]+(?:-[A-Z])?|ANEXO(?:\s+[IVX]+)?))'
    r'\s*(?:<br>\s*([^<]*))?.{0,300}?</td>', re.S)
PGDL_HEADER_POINTS = re.compile(  # portarias: bare numbered points + Mapa annex
    r'<td class=txt_base_b_l[^>]*>.{0,200}?'
    r'(?:(\d+)\.º(?:-([A-Z]+))?(?:\s*\([^<)]{0,80}\))?'
    r'|(TABELA\s+[IVX]+(?:-[A-Z])?|ANEXO(?:\s+[IVX]+)?|MAPA|Mapa))'
    r'\s*(?:<br>\s*([^<]*))?.{0,300}?</td>', re.S)

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
    # follow the site's own pager hrefs (ficha=, not pagina=, drives the
    # offset) and keep harvesting from every fetched page: on long codes the
    # first page's pager window does not list all pages
    hrefs, done = {}, {1}
    def _harvest(page_text):
        for m in re.finditer(r"href='(lei_mostra_articulado\.php\?[^']*nid=%s"
                             r"[^']*)'" % cfg["nid"], page_text):
            pm = re.search(r"pagina=(\d+)", m.group(1))
            if pm:
                hrefs.setdefault(int(pm.group(1)), m.group(1))
    _harvest(pages[0])
    while True:
        todo = sorted(p for p in hrefs if p not in done)
        if not todo:
            break
        if len(done) > 80:
            raise DonnaError("pager runaway: more than 80 pages discovered")
        p = todo[0]
        done.add(p)
        time.sleep(0.5)
        url = "https://www.pgdlisboa.pt/leis/" + html.unescape(hrefs[p])
        for attempt in (2, 5, 0):
            try:
                raw = fetch(url)
                break
            except OSError:
                if not attempt:
                    raise
                time.sleep(attempt)
        raws.append(raw)
        pages.append(raw.decode("iso-8859-1", errors="replace"))
        _harvest(pages[-1])
    expected = []
    toc_re = (r'<option value="%sA\d+">(?:Artigo\s+)?(\d+)\.º(?:-([A-Z]+))?'
              if cfg.get("points") else
              r'<option value="%sA\d+">Artigo\s+(\d+)\.º(?:-([A-Z]+))?')
    for m in re.finditer(toc_re % cfg["nid"], pages[0]):
        n = m.group(1) + (f"-{m.group(2)}" if m.group(2) else "")
        if n not in expected:
            expected.append(n)
    counts = {"struct": 0}
    fragments, seen = [], set()
    for page in pages:
        header_re = PGDL_HEADER_POINTS if cfg.get("points") else PGDL_HEADER
        heads = list(header_re.finditer(page))
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
            chunk = page[m.end():end]
            body = _pgdl_clean(chunk, counts)
            # PGDL appends an amendment-history footer to each article
            cut = re.search(r"Contém as alterações|Consultar versões anteriores"
                            r"|Consultar esta disposição", body)
            if cut:
                body = canonical(body[:cut.start()])
                counts["hist"] = counts.get("hist", 0) + 1
            if not body and kind == "annex":
                # scanned annexes are served as images; anchor their bytes
                lines = []
                for src_m in re.finditer(r"<img src='([^']+)'", chunk):
                    # src is relative to /leis/ ('../leis/x.gif' or ' imagens/x.gif')
                    href = src_m.group(1).strip().replace("../", "")
                    if not href.startswith("leis/"):
                        href = "leis/" + href
                    img = fetch("https://www.pgdlisboa.pt/" + href.replace(" ", "%20"))
                    raws.append(img)
                    name = href.rsplit("/", 1)[-1]
                    lines.append(f"[imagem: {name} sha256:{sha256(img)}]")
                    counts["img"] = counts.get("img", 0) + 1
                body = canonical("\n".join(lines))
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
              "image_assets_anchored": counts.get("img", 0),
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

GI_PARSER = "donna-govinfo/0.2.2"

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
        hdr = html.unescape(hdr)  # &#8211; and friends before the dash pass
        hdr = re.sub(r"[\u2010-\u2015\u2212]", "-", hdr)  # §78dd–2 uses an en dash
        m = re.match(r"§+\s*([0-9A-Za-z]+(?:-[0-9A-Za-z]+)?)[.,\s]*(.*)", hdr)
        if not m:
            continue
        number, heading = m.group(1), m.group(2).strip().rstrip("]")
        if number in seen:
            continue
        seen.add(number)
        cut = cut_re.search(body)
        if cut:
            notes_cut += 1
            body = body[:cut.start()]
        body = re.sub(r"<[^>]*$", "", body)  # tag opened by the cut point
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

WY_PARSER = "donna-wy-pdf/0.4.0"
WY_BASE = "https://wyoleg.gov/statutes/compress/"

def _monotone_chain(items, keyfn):
    """Longest non-decreasing subsequence of items by keyfn (O(n log n),
    deterministic). Wrapped cross-references ("...see W.S.\n17-29-702.")
    start lines too and look like headers; a greedy monotone filter lets one
    such outlier reject every real header that follows it, the LIS keeps
    the long true run and drops the outlier."""
    import bisect
    keys = [keyfn(x) for x in items]
    tails, tails_idx, prev = [], [], [-1] * len(items)
    for i, k in enumerate(keys):
        j = bisect.bisect_right(tails, k)
        if j == len(tails):
            tails.append(k)
            tails_idx.append(i)
        else:
            tails[j] = k
            tails_idx[j] = i
        prev[i] = tails_idx[j - 1] if j else -1
    out, i = [], tails_idx[-1] if tails_idx else -1
    while i != -1:
        out.append(items[i])
        i = prev[i]
    return out[::-1]

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
        # -layout preserves reading order: default mode reorders hanging-
        # indent continuations ahead of their lead-in lines (LAB via donna-29)
        r = subprocess.run(["pdftotext", "-layout", "-enc", "UTF-8", pdf, "-"],
                           capture_output=True, check=True)
    text = r.stdout.decode("utf-8", errors="replace").replace("\f", "\n")
    tnum = cfg["ws_title"]
    head_re = re.compile(r"^[ \t]*(%s-\d+(?:\.\d+)?-\d+)\.(?:[ \t]+(\S.*))?$"
                         % re.escape(tnum), re.M)
    def key(number):
        parts = number.split("-")
        return tuple(float(x) if "." in x else int(x) for x in parts[1:])
    heads = list(head_re.finditer(text))
    picked = _monotone_chain(heads, lambda m: key(m.group(1)))
    fragments, by_num = [], {}
    for i, m in enumerate(picked):
        number = m.group(1)
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
        # layout mode wraps headings: continuation lines run until a blank
        # line or the first subsection marker
        if lines and not lines[0].strip():
            lines = lines[1:]  # the newline ending the header line itself
        while lines and lines[0].strip() and \
                not re.match(r"\s*\(", lines[0]) and \
                not head_re.match(lines[0]):
            heading += " " + lines[0].strip()
            lines = lines[1:]
        body = canonical("\n".join(lines))
        if not body:  # repealed sections carry only their status line
            body = heading
        frag = {"kind": "section", "number": number,
                "heading": heading.rstrip("."), "text": body}
        prev = by_num.get(number)
        if prev is None:
            by_num[number] = frag
            fragments.append(frag)
        elif not prev["text"] and body:
            # a stray bare header line can precede the real section
            prev.update(frag)
    chapters = {f["number"].split("-")[1] for f in fragments}
    checks = {"tier": "C", "extractor": "pdftotext",
              "sections": len(fragments), "chapters": len(chapters),
              "headers_rejected": len(heads) - len(picked),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]]}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "en",
            "source_url": WY_BASE + cfg["file"], "raw": raw,
            "checks": checks, "parser": WY_PARSER}

# ---------------------------------------------------------------- UK adapter (CLML)

UK_PARSER = "donna-uk-clml/0.1.0"
UK_NS = "{http://www.legislation.gov.uk/namespaces/legislation}"
UK_SKIP = {UK_NS + "Commentary", UK_NS + "CommentaryRef"}
UK_BLOCK_END = {UK_NS + t for t in ("Text", "Para", "ListItem", "tr", "Title",
                                    "BlockText", "AppendText")}

def _uk_serialize(el, out, counts, own_number=False):
    tag = el.tag
    if tag in UK_SKIP:
        counts["commentary" if tag.endswith("Commentary") else "refs"] += 1
        if el.tail:
            out.append(el.tail)
        return
    if tag == UK_NS + "Pnumber":
        if not own_number:
            out.append("(" + "".join(el.itertext()).strip() + ") ")
        if el.tail:
            out.append(el.tail)
        return
    if tag == UK_NS + "td":
        out.append(" ")
    if el.text:
        out.append(el.text)
    for c in el:
        _uk_serialize(c, out, counts)
    if tag in UK_BLOCK_END:
        out.append("\n")
    if el.tail:
        out.append(el.tail)

def _uk_text(el, counts, skip_own_number=False):
    out = []
    for c in el:
        if skip_own_number and c.tag == UK_NS + "Pnumber":
            continue
        if c.tag == UK_NS + "Title":
            continue
        _uk_serialize(c, out, counts)
    return canonical("".join(out))

def uk_acquire(year, wtype, num, version):
    """legislation.gov.uk CLML XML (Tier A). @revised = the current revised
    text (label carries dct:valid); @enacted = as originally enacted."""
    base = f"https://www.legislation.gov.uk/{wtype}/{year}/{num}"
    url = base + ("/enacted/data.xml" if version == "enacted" else "/data.xml")
    raw = fetch(url, ua=BROWSER_UA)
    root = ET.fromstring(raw)
    dc = "{http://purl.org/dc/elements/1.1/}"
    dct = "{http://purl.org/dc/terms/}"
    title = (root.findtext(f".//{dc}title") or "").strip()
    parent = {c: p for p in root.iter() for c in p}
    counts = {"commentary": 0, "refs": 0}
    fragments = []
    body = root.find(f".//{UK_NS}Body")
    if body is None:
        raise DonnaError("no <Body> element - CLML layout may have changed")
    for p1 in body.iter(UK_NS + "P1"):
        pid = p1.get("id") or ""
        if not pid.startswith("section-"):
            continue
        number = pid[len("section-"):]
        heading = ""
        grp = parent.get(p1)
        if grp is not None and grp.tag == UK_NS + "P1group":
            t = grp.find(UK_NS + "Title")
            if t is not None:
                heading = canonical("".join(t.itertext()))
        text = _uk_text(p1, counts, skip_own_number=True)
        fragments.append({"kind": "section", "number": number,
                          "heading": heading, "text": text})
    for sched in root.iter(UK_NS + "Schedule"):
        sid = sched.get("id") or ""
        if not sid.startswith("schedule-") or "-" in sid[len("schedule-"):]:
            continue
        number = sid[len("schedule-"):]
        t = sched.find(f"{UK_NS}TitleBlock/{UK_NS}Title")
        heading = canonical("".join(t.itertext())) if t is not None else ""
        sb = sched.find(UK_NS + "ScheduleBody")
        text = _uk_text(sb, counts) if sb is not None else ""
        fragments.append({"kind": "schedule", "number": number,
                          "heading": heading, "text": text})
    if version == "enacted":
        label = "enacted"
    else:
        valid = (root.findtext(f".//{dct}valid") or
                 root.get("RestrictStartDate") or "").strip()
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", valid):
            raise DonnaError("revised source did not declare a valid-from date")
        label = f"revised-{valid}"
    seq = sorted({int(re.match(r"\d+", f["number"]).group(0))
                  for f in fragments if f["kind"] == "section"
                  and re.match(r"\d+", f["number"])})
    ukm = "{http://www.legislation.gov.uk/namespaces/metadata}"
    declared = root.find(f".//{ukm}BodyParagraphs")
    checks = {"tier": "A",
              "sections": sum(1 for f in fragments if f["kind"] == "section"),
              "schedules": sum(1 for f in fragments if f["kind"] == "schedule"),
              "declared_body_paragraphs": int(declared.get("Value"))
              if declared is not None else None,
              "numbering_gaps": numbering_gaps(seq),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]],
              "commentaries_stripped": counts["commentary"],
              "commentary_refs_stripped": counts["refs"]}
    return {"work_meta": {"title": title, "aliases": ""},
            "fragments": fragments, "label": label, "lang": "en",
            "source_url": url, "raw": raw, "checks": checks, "parser": UK_PARSER}

# ---------------------------------------------------------------- EUR-Lex adapter (ELI)

EU_PARSER = "donna-eurlex-eli/0.1.0"
EU_BASE = "https://eur-lex.europa.eu/eli/"

def _eu_strip(fragment_html):
    t = re.sub(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", "", fragment_html,
               flags=re.S)
    t = re.sub(r"</(?:p|div|td|tr|li|table)>", "\n", t, flags=re.I)
    t = re.sub(r"<br\s*/?>", "\n", t, flags=re.I)
    t = re.sub(r"<[^>]+>", "", t)
    return canonical(html.unescape(t))

def eurlex_acquire(cfg, version):
    """EUR-Lex ELI HTML (Tier B). @consolidated = the consolidated text at
    cfg['consolidated'] (YYYY-MM-DD); @enacted = the Official Journal text."""
    if version == "enacted":
        url = f"{EU_BASE}{cfg['eli']}/oj/eng"
        label = "enacted"
    else:
        url = f"{EU_BASE}{cfg['eli']}/{cfg['consolidated']}/eng"
        label = "consolidated"
    raw = fetch(url, ua=BROWSER_UA)
    page = raw.decode("utf-8", errors="replace")
    heads = list(re.finditer(
        r'<div class="eli-subdivision" id="art_(\d+[a-z]*)">', page))
    if not heads:
        raise DonnaError("no eli-subdivision article anchors - page layout may"
                         " have changed (EUR-Lex answers 202 while rendering;"
                         " retry)")
    end_re = re.compile(r'<div class="eli-subdivision" id="(?!art_)|class="oj-final"'
                        r'|class="final"|id="fin_|class="oj-signatory"'
                        r'|<div class="eli-subdivision" id="art_')
    fragments, seen = [], set()
    for i, m in enumerate(heads):
        number = m.group(1)
        if number in seen:
            continue
        seen.add(number)
        e = end_re.search(page, m.end())
        chunk = page[m.end():e.start() if e else len(page)]
        hm = re.search(r'class="(?:oj-sti-art|stitle-article-norm)"[^>]*>(.*?)</p>',
                       chunk, re.S)
        heading = _eu_strip(hm.group(1)) if hm else ""
        chunk = re.sub(r'<p[^>]*class="(?:oj-ti-art|title-article-norm)"[^>]*>.*?</p>',
                       "", chunk, count=1, flags=re.S)
        if hm:
            chunk = chunk.replace(hm.group(0), "", 1)
        fragments.append({"kind": "article", "number": number, "heading": heading,
                          "text": _eu_strip(chunk)})
    seq = sorted({int(re.match(r"\d+", f["number"]).group(0)) for f in fragments})
    checks = {"tier": "B", "articles": len(fragments),
              "numbering_gaps": numbering_gaps(seq),
              "empty_fragments": [f["number"] for f in fragments if not f["text"]]}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": label, "lang": "en",
            "source_url": url, "raw": raw, "checks": checks, "parser": EU_PARSER}

# ---------------------------------------------------------------- Delaware adapter

DE_PARSER = "donna-delcode/0.1.0"
DE_BASE = "https://delcode.delaware.gov/"

def delcode_acquire(cfg, version):
    """delcode.delaware.gov chapter pages (Tier B). Coverage is the chapters
    listed in cfg['chapters'] - declared partial in checks and title."""
    if version != "consolidated":
        raise DonnaError("this source serves @consolidated only")
    sec_re = re.compile(r'<div class="SectionHead" id="([\w.-]+)">(.*?)</div>(.*?)'
                        r'(?=<div class="SectionHead"|<div class="footer"|'
                        r'<footer|</main>|$)', re.S)
    fragments, seen, pages, raw_all = [], set(), [], []
    toc_declared = toc_parsed = 0
    for ch in cfg["chapters"]:
        idx_url = f"{DE_BASE}title{cfg['title_no']}/{ch}/index.html"
        idx = fetch(idx_url, ua=BROWSER_UA)
        raw_all.append(idx)
        idx_page = idx.decode("utf-8", errors="replace")
        subs = sorted(set(re.findall(r'href="[^"]*/(sc\d+)/index\.html"', idx_page)))
        urls = [f"{DE_BASE}title{cfg['title_no']}/{ch}/{s}/index.html" for s in subs] \
            or [idx_url]
        for u in urls:
            page = idx_page if u == idx_url else None
            if page is None:
                r = fetch(u, ua=BROWSER_UA)
                raw_all.append(r)
                page = r.decode("utf-8", errors="replace")
            pages.append(u)
            toc_declared += len(re.findall(r'<a href="#[\w.-]+">\s*§', page))
            for m in sec_re.finditer(page):
                number = m.group(1)
                if number in seen:
                    continue
                seen.add(number)
                toc_parsed += 1
                head = _eu_strip(m.group(2))
                head = re.sub(r"^§\s*[\w.-]+\.\s*", "", head)
                paras = re.findall(r"<p[^>]*>(.*?)</p>", m.group(3), re.S)
                text = canonical("\n".join(_eu_strip(p) for p in paras))
                fragments.append({"kind": "section", "number": number,
                                  "heading": head.rstrip("."), "text": text})
    checks = {"tier": "B", "coverage": "partial", "chapters": cfg["chapters"],
              "pages_fetched": len(pages), "sections": len(fragments),
              "toc_declared": toc_declared, "toc_parsed": toc_parsed,
              "empty_fragments": [f["number"] for f in fragments if not f["text"]]}
    return {"work_meta": {"title": cfg["title"], "aliases": cfg["aliases"]},
            "fragments": fragments, "label": "consolidated", "lang": "en",
            "source_url": f"{DE_BASE}title{cfg['title_no']}/", "raw": b"".join(raw_all),
            "checks": checks, "parser": DE_PARSER}

# ---------------------------------------------------------------- work registry

ADAPTERS = {"ie": ie_acquire, "uk": uk_acquire}  # pattern adapters: any Work in the jurisdiction

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
    ("pt", "1988", "dec-lei", "442-a"): {
        "source": pt_at_acquire,
        "title": "Código do Imposto sobre o Rendimento das Pessoas Singulares"
                 " (Código do IRS)",
        "aliases": "CIRS,CODIGO DO IRS,CÓDIGO DO IRS",
        "index": PT_BASE + "/pt/informacao_fiscal/codigos_tributarios/cirs_rep"
                 "/Pages/codigo-do-irs-indice.aspx",
        "slug": "irs",
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
    ("us", "1926", "usc", "15"): {
        "source": govinfo_acquire, "package": "USCODE-2023-title15",
        "title": "United States Code Title 15 - Commerce and Trade"
                 " (2023 edition, GovInfo)",
        "aliases": "15 USC,TITLE 15,COMMERCE AND TRADE",
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
    ("pt", "1989", "dec-lei", "215"): {
        "source": pt_at_acquire, "harvest_all": True, "slug": "ebf",
        "index": PT_BASE + "/pt/informacao_fiscal/codigos_tributarios/bf_rep"
                 "/Pages/estatuto-dos-beneficios-fiscais-indice.aspx",
        "title": "Estatuto dos Benefícios Fiscais (DL n.º 215/89)",
        "aliases": "EBF,ESTATUTO DOS BENEFICIOS FISCAIS,"
                   "ESTATUTO DOS BENEFÍCIOS FISCAIS",
    },
    ("pt", "1998", "dec-lei", "398"): {
        "source": pt_at_acquire, "slug": "lgt",
        "index": PT_BASE + "/pt/informacao_fiscal/codigos_tributarios/lgt"
                 "/Pages/lei-geral-tributaria-indice.aspx",
        "title": "Lei Geral Tributária (DL n.º 398/98)",
        "aliases": "LGT,LEI GERAL TRIBUTARIA,LEI GERAL TRIBUTÁRIA",
    },
    ("pt", "1996", "portaria", "94"): {
        "source": pgdl_acquire, "nid": "192",
        "points": True,
        "title": "Diagnóstico e Exames Periciais - Limites Quantitativos"
                 " Máximos (Portaria n.º 94/96)",
        "aliases": "PORTARIA 94/96,LIMITES QUANTITATIVOS,MAPA DA PORTARIA",
    },
    ("pt", "1986", "lei", "44"): {
        "source": pgdl_acquire, "nid": "1712",
        "title": "Regime do Estado de Sítio e do Estado de Emergência"
                 " (Lei n.º 44/86)",
        "aliases": "ESTADO DE EMERGENCIA,ESTADO DE EMERGÊNCIA,ESTADO DE SITIO",
    },
    ("pt", "1982", "dec-lei", "433"): {
        "source": pgdl_acquire, "nid": "166",
        "title": "Regime Geral das Contra-Ordenações (DL n.º 433/82)",
        "aliases": "RGCO,REGIME GERAL DAS CONTRA-ORDENACOES,"
                   "REGIME GERAL DAS CONTRA-ORDENAÇÕES,DL 433/82",
    },
    ("pt", "2001", "dec-lei", "130-a"): {
        "source": pgdl_acquire, "nid": "193",
        "title": "Comissões para a Dissuasão da Toxicodependência - organização"
                 " e processo (DL n.º 130-A/2001)",
        "aliases": "DL 130-A/2001,CDT,COMISSOES DE DISSUASAO,"
                   "COMISSÕES DE DISSUASÃO",
    },
    ("pt", "2007", "lei", "37"): {
        "source": pgdl_acquire, "nid": "1066",
        "title": "Lei do Tabaco - exposição ao fumo ambiental (Lei n.º 37/2007)",
        "aliases": "LEI DO TABACO,LEI 37/2007,LEI ANTI-TABACO",
    },
    ("pt", "1966", "dec-lei", "47344"): {
        "source": pgdl_acquire, "nid": "775",
        "title": "Código Civil (DL n.º 47344/66)",
        "aliases": "CC,CODIGO CIVIL,CÓDIGO CIVIL",
    },
    ("pt", "2013", "lei", "41"): {
        "source": pgdl_acquire, "nid": "1959",
        "title": "Código de Processo Civil (Lei n.º 41/2013)",
        "aliases": "CPC,CODIGO DE PROCESSO CIVIL,CÓDIGO DE PROCESSO CIVIL",
    },
    ("pt", "1996", "lei", "24"): {
        "source": pgdl_acquire, "nid": "726",
        "title": "Lei de Defesa do Consumidor (Lei n.º 24/96)",
        "aliases": "LDC,LEI DE DEFESA DO CONSUMIDOR",
    },
    ("pt", "2021", "dec-lei", "84"): {
        "source": pgdl_acquire, "nid": "3471",
        "title": "Compra e Venda de Bens, Conteúdos e Serviços Digitais -"
                 " conformidade (DL n.º 84/2021)",
        "aliases": "DL 84/2021,BENS DE CONSUMO",
    },
    ("pt", "2001", "lei", "78"): {
        "source": pgdl_acquire, "nid": "724",
        "title": "Lei dos Julgados de Paz (Lei n.º 78/2001)",
        "aliases": "JULGADOS DE PAZ,LJP,LEI DOS JULGADOS DE PAZ",
    },
    ("us", "1947", "usc", "9"): {
        "source": govinfo_acquire, "package": "USCODE-2023-title9",
        "title": "United States Code Title 9 - Arbitration (Federal Arbitration"
                 " Act; 2023 edition, GovInfo)",
        "aliases": "9 USC,TITLE 9,FAA,FEDERAL ARBITRATION ACT",
    },
    ("us", "1976", "usc", "17"): {
        "source": govinfo_acquire, "package": "USCODE-2023-title17",
        "title": "United States Code Title 17 - Copyrights (2023 edition,"
                 " GovInfo)",
        "aliases": "17 USC,TITLE 17,COPYRIGHT ACT,COPYRIGHTS",
    },
    ("us", "1948", "usc", "18"): {
        "source": govinfo_acquire, "package": "USCODE-2023-title18",
        "title": "United States Code Title 18 - Crimes and Criminal Procedure"
                 " (incl. ch. 90 Protection of Trade Secrets / DTSA; 2023"
                 " edition, GovInfo)",
        "aliases": "18 USC,TITLE 18,DTSA,DEFEND TRADE SECRETS ACT",
    },
    ("eu", "2016", "reg", "679"): {
        "source": eurlex_acquire, "eli": "reg/2016/679",
        "consolidated": "2016-05-04",
        "title": "Regulation (EU) 2016/679 - General Data Protection Regulation"
                 " (GDPR)",
        "aliases": "GDPR,RGPD,GENERAL DATA PROTECTION REGULATION,"
                   "REGULATION (EU) 2016/679,REG 2016/679",
    },
    ("de", "1953", "title", "6"): {
        "source": delcode_acquire, "title_no": "6", "chapters": ["c027"],
        "title": "Delaware Code Title 6 - Commerce and Trade (partial: ch. 27"
                 " Contracts)",
        "aliases": "6 DEL C,6 DEL. C.,DELAWARE TITLE 6,DEL CODE TITLE 6",
    },
    ("de", "1953", "title", "10"): {
        "source": delcode_acquire, "title_no": "10", "chapters": ["c057"],
        "title": "Delaware Code Title 10 - Courts and Judicial Procedure"
                 " (partial: ch. 57 Uniform Arbitration Act)",
        "aliases": "10 DEL C,10 DEL. C.,DELAWARE TITLE 10,DELAWARE UNIFORM"
                   " ARBITRATION ACT",
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

HASH_FORMAT = 2

def _expression_hashes(fragments, hash_format=HASH_FORMAT):
    """Format 2 binds identity to content: kind, number, heading, order and
    text hash per fragment. Format 1 (legacy) covered ordered text hashes only."""
    frag_hashes = [sha256(f["text"]) for f in fragments]
    if hash_format == 1:
        return frag_hashes, sha256("\n".join(frag_hashes))
    lines = [f"{f['kind']}|{f['number']}|{sha256(f['heading'] or '')}|{h}"
             for f, h in zip(fragments, frag_hashes)]
    return frag_hashes, sha256("\n".join(lines))

def _stored_hash_format(con, expr_id):
    row = con.execute("SELECT payload_json FROM attestations WHERE"
                      " expression_id = ? ORDER BY id DESC", (expr_id,)).fetchone()
    if row and row[0]:
        return json.loads(row[0]).get("hash_format", 1)
    return 1

def _gate_ingest(res):
    """Extraction failures must never overwrite stored law (LAB-25 F3)."""
    reasons = []
    if not res["fragments"]:
        reasons.append("zero fragments extracted")
    for key in ("unparsed_pages", "toc_missing"):
        if res["checks"].get(key):
            reasons.append(f"{key}: {res['checks'][key]}")
    empties = res["checks"].get("empty_fragments") or []
    if len(empties) > max(4, len(res["fragments"]) // 5):
        reasons.append(f"mass-empty extraction: {len(empties)} of"
                       f" {len(res['fragments'])} fragments empty")
    return reasons

def ingest(con, work_path, allow_defects=False):
    try:
        work_id, version, res = _acquire(work_path)
    except DonnaError as e:
        sys.exit(str(e))
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    gate = _gate_ingest(res)
    if gate and not allow_defects:
        sys.exit("ingest refused, stored corpus preserved (--allow-defects to"
                 " override):\n  - " + "\n  - ".join(gate))
    if gate:
        res["checks"]["gate_overridden"] = gate

    expr_id = f"{work_id}@{res['label']}:{res['lang']}"
    frag_hashes, expr_hash = _expression_hashes(res["fragments"])
    existing = con.execute("SELECT content_hash FROM expressions WHERE id = ?",
                           (expr_id,)).fetchone()
    if existing and existing[0] != expr_hash:
        # immutable version identities (LAB-25 F4): never overwrite changed text
        if res["label"].startswith("consolidated"):
            dated = f"consolidated-{fetched_at[:10]}"
            dated_id = f"{work_id}@{dated}:{res['lang']}"
            clash = con.execute("SELECT content_hash FROM expressions WHERE"
                                " id = ?", (dated_id,)).fetchone()
            if clash and clash[0] != expr_hash:
                sys.exit(f"conflicting content for {dated_id} on the same day;"
                         " investigate with 'donna check' before re-ingesting")
            res["label"], expr_id = dated, dated_id
            print(f"content changed: prior expression preserved, new version"
                  f" {expr_id}", file=sys.stderr)
        else:
            sys.exit(f"content changed under immutable version {expr_id};"
                     " a dated version id is required — investigate with"
                     " 'donna check'")

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
             "content_hash": expr_hash, "hash_format": HASH_FORMAT,
             "parser": res["parser"], "checks": res["checks"]},
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

def expression_for(con, work_id, version, strict=False):
    """Version-prefix match (shorthand like 'revised' expands to the latest
    dated revision). strict=True is for explicit version requests: no
    fall-back to whatever happens to be ingested (LAB-25 F5)."""
    row = con.execute("SELECT id FROM expressions WHERE work_id = ? AND version"
                      " LIKE ? ORDER BY version DESC",
                      (work_id, version + "%")).fetchone()
    if row:
        return row[0]
    rows = con.execute("SELECT id FROM expressions WHERE work_id = ?",
                       (work_id,)).fetchall()
    if not strict and len(rows) == 1:  # Q6 rule: unqualified citations only
        return rows[0][0]
    if rows:
        raise DonnaError(f"no {version} expression for {work_id!r}; have: "
                         + ", ".join(r[0] for r in rows))
    raise DonnaError(f"no expressions ingested for {work_id!r}")

def _default_expression(con, work_id):
    """Unqualified citations get the work's current expression: enacted when
    one exists, else the latest consolidated, else the only expression."""
    for pref in ("enacted", "consolidated"):
        row = con.execute("SELECT id FROM expressions WHERE work_id = ? AND"
                          " version LIKE ? ORDER BY version DESC",
                          (work_id, pref + "%")).fetchone()
        if row:
            return row[0]
    return expression_for(con, work_id, "enacted")

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
        expr = expression_for(con, f"ie/{year}/act/{num}", version, strict=True)
        return {"id": _fragment_id(con, expr, sec) if sec else expr}
    m = re.search(r"legislation\.gov\.uk/(ukpga|uksi|asp|nisi|anaw|asc)/(\d{4})/(\d+)"
                  r"(?:/section/(\w+?))?"
                  r"(?:/(enacted|made|\d{4}-\d{2}-\d{2}))?(?:[?#]|$|\s)", c)
    if m:
        wtype, year, num, sec, uver = m.groups()
        if uver in ("enacted", "made"):
            want = "enacted"
        elif uver:  # explicit point-in-time
            want = f"revised-{uver}"
        else:
            want = "revised"
        expr = expression_for(con, f"uk/{year}/{wtype}/{num}", want, strict=True)
        return {"id": _fragment_id(con, expr, sec) if sec else expr}
    m = re.search(r"eur-lex\.europa\.eu/eli/(reg|dir|dec|dec_impl|reg_impl)/(\d{4})/(\d+)"
                  r"(?:.*?/art_(\d+))?", c)
    if m:
        wtype, year, num, art = m.groups()
        expr = expression_for(con, f"eu/{year}/{wtype}/{num}", "consolidated")
        return {"id": _fragment_id(con, expr, art) if art else expr}
    m = re.search(r"\b(\d{1,2})\s*Del\.?\s*C\.?\s*§*\s*(\d+[A-Za-z]*)", c)
    if m:
        row = con.execute("SELECT id FROM works WHERE jurisdiction = 'de' AND"
                          " number = ?", (m.group(1),)).fetchone()
        if row:
            expr = _default_expression(con, row[0])
            return {"id": _fragment_id(con, expr, m.group(2))}
    m = re.fullmatch(r"([\w-]+/\d{4}/[\w-]+/[\w-]+)(?:@([\w:.-]+))?(#[\w.-]+)?", c)
    if m:
        path, version, frag = m.groups()
        if version:
            exact = f"{path}@{version}"
            if con.execute("SELECT 1 FROM expressions WHERE id = ?",
                           (exact,)).fetchone():
                expr = exact
            else:  # expand shorthand like @revised strictly (LAB-25 F6)
                expr = expression_for(con, path, version.split(":")[0],
                                      strict=True)
        else:
            expr = _default_expression(con, path)
        if frag:
            fid = f"{expr}{frag}"
            if not con.execute("SELECT 1 FROM fragments WHERE id = ?",
                               (fid,)).fetchone():
                raise DonnaError(f"unknown fragment {fid!r}")
            return {"id": fid}
        return {"id": expr}
    m = re.search(r"(?:W\.?S\.?\s*)?\b(\d{1,2}(?:\.\d+)?)-(\d+(?:\.\d+)?-\d+)\b", c)
    if m:
        tnum = m.group(1).replace(".", "-")
        row = con.execute("SELECT id FROM works WHERE jurisdiction = 'wy' AND"
                          " number = ?", (tnum,)).fetchone()
        if row:
            expr = _default_expression(con, row[0])
            return {"id": _fragment_id(con, expr, f"{m.group(1)}-{m.group(2)}")}
    m = re.search(r"(?:(\d+)\s*U\.?S\.?C\.?|\bIRC\b)\s*§?\s*"
                  r"(\d+[A-Za-z]*(?:-\d+)?)", c)
    if m:
        title = m.group(1) or "26"
        row = con.execute("SELECT id FROM works WHERE type = 'usc' AND"
                          " number = ?", (title,)).fetchone()
        if row:
            expr = _default_expression(con, row[0])
            return {"id": _fragment_id(con, expr, m.group(2))}
    m = re.search(r"(?:^|\b)(?:s\.?|section|art\.?|article|artigo)\s*"
                  r"(\d+[A-Z]*)(?:\.?º)?(?:\s*-\s*([A-Za-z]))?"
                  r"\s+(?:of\s+(?:the\s+)?|d[oa]\s+)?(.+)", c, re.IGNORECASE)
    if m:
        sec = m.group(1) + (f"-{m.group(2).upper()}" if m.group(2) else "")
        name = m.group(3).strip()
    else:
        sec, name = None, c
    # structured Portuguese citation: "DL 130-A/2001", "Lei n.º 37/2007",
    # "Decreto-Lei n.º 433/82", "Portaria 94/96"
    pm = re.search(r"\b(DL|Decreto-Lei|Lei Orgânica|Lei|Portaria|Decreto"
                   r" Regulamentar|DR)\s*(?:n\.?[ºo°]?\s*)?(\d+(?:-[A-Za-z])?)"
                   r"/(\d{2,4})\b", name, re.IGNORECASE)
    if pm:
        ptype = {"dl": "dec-lei", "decreto-lei": "dec-lei", "lei": "lei",
                 "lei orgânica": "lei-organica", "portaria": "portaria",
                 "decreto regulamentar": "dec-regulamentar",
                 "dr": "dec-regulamentar"}[pm.group(1).lower()]
        pyear = int(pm.group(3))
        if pyear < 100:
            pyear += 1900 if pyear > 35 else 2000
        row = con.execute("SELECT id FROM works WHERE id LIKE 'pt/%' AND type = ?"
                          " AND number = ? AND year = ?",
                          (ptype, pm.group(2).lower(), pyear)).fetchone()
        if row:
            expr = _default_expression(con, row[0])
            return {"id": _fragment_id(con, expr, sec) if sec else expr}
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
        expr = _default_expression(con, work_id)
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
    if not needle:
        raise DonnaError("empty quotation cannot be verified")
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

def _fts(con, q):
    return con.execute("SELECT id, heading, snippet(fragments_fts, 2, '[', ']',"
                       " '…', 12) FROM fragments_fts WHERE fragments_fts MATCH ?"
                       " ORDER BY rank LIMIT 10", (q,)).fetchall()

def q_search(con, query):
    if not query.strip():
        raise DonnaError("empty search query")
    if HAS_FTS:
        try:
            rows = _fts(con, query)
        except sqlite3.OperationalError:
            # ordinary terms like cross-border are FTS syntax; quote per token
            safe = " ".join('"' + t.replace('"', '') + '"'
                            for t in query.split() if t.replace('"', ''))
            if not safe:
                raise DonnaError("empty search query")
            try:
                rows = _fts(con, safe)
            except sqlite3.OperationalError as e:
                raise DonnaError(f"invalid search query: {e}")
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
    expr = con.execute("SELECT content_hash, source_url FROM expressions WHERE"
                       " id = ?", (expr_id,)).fetchone()
    if not expr:
        raise DonnaError(f"unknown expression {expr_id!r}")
    rows = con.execute("SELECT id, kind, number, heading, text, content_hash"
                       " FROM fragments WHERE expression_id = ? ORDER BY ord",
                       (expr_id,)).fetchall()
    mismatches = [fid for fid, _, _, _, text, h in rows if sha256(text) != h]
    frags = [{"kind": k, "number": n, "heading": hd, "text": t}
             for _, k, n, hd, t, _ in rows]
    att_row = con.execute("SELECT payload_json, signature, signer FROM attestations"
                          " WHERE expression_id = ? ORDER BY id DESC",
                          (expr_id,)).fetchone()
    payload = json.loads(att_row[0]) if att_row and att_row[0] else {}
    fmt = payload.get("hash_format", 1)
    _, computed = _expression_hashes(frags, hash_format=fmt)
    expr_ok = computed == expr[0]
    att = {"present": bool(att_row), "signed": False, "trust": "unsigned",
           "hash_format": fmt}
    authenticated = False
    if payload:
        att["payload_matches_corpus"] = (
            payload.get("content_hash") == expr[0]
            and payload.get("expression_id", expr_id) == expr_id
            and payload.get("source_url", expr[1]) == expr[1])
        if att_row[1]:
            sig_ok, trusted, detail = verify_signature(
                att_row[0].encode(), att_row[1], att_row[2])
            authenticated = sig_ok and trusted
            att.update(signed=True, signature_ok=sig_ok, detail=detail,
                       trust="signed-trusted" if authenticated
                       else "signed-untrusted" if sig_ok
                       else "signature-invalid")
    ok = (not mismatches and expr_ok
          and att.get("payload_matches_corpus", True)
          and att.get("signature_ok", True))
    return {"expression": expr_id, "ok": ok, "authenticated": authenticated,
            "fragments_checked": len(rows),
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
    _, expr_hash = _expression_hashes(res["fragments"],
                                      hash_format=_stored_hash_format(con, stored_id))
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

def q_derive(con, fid, kind, producer, source_sha, content):
    get_fragment(con, fid)  # must exist
    with con:
        con.execute("INSERT INTO derived(fragment_id, kind, producer,"
                    " source_sha256, content, created_at) VALUES (?,?,?,?,?,?)",
                    (fid, kind, producer, source_sha, content,
                     datetime.now(timezone.utc).isoformat(timespec="seconds")))
    return {"fragment": fid, "kind": kind, "stored": len(content)}

def q_derived(con, fid):
    rows = con.execute("SELECT kind, producer, source_sha256, content,"
                       " created_at FROM derived WHERE fragment_id = ?"
                       " ORDER BY id DESC", (fid,)).fetchall()
    if not rows:
        raise DonnaError(f"no derived artifacts for {fid!r}")
    return {"fragment": fid,
            "artifacts": [{"kind": k, "producer": p, "source_sha256": s,
                           "content": c, "created_at": at}
                          for k, p, s, c, at in rows]}

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
    {"name": "donna_derived",
     "description": "NON-CANONICAL: derived artifacts (e.g. LLM transcriptions"
                    " of scanned annexes) attached to a fragment, with producer"
                    " and source-image hash. Never quotable law - verify"
                    " against the anchored image.",
     "inputSchema": _S("id", "fragment id")},
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
    if name == "donna_derived":
        return q_derived(con, args["id"])
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
            except Exception as e:  # never let a tool call kill the server
                result = {"content": [{"type": "text",
                                       "text": f"{type(e).__name__}: {e}"}],
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
    ing = sub.add_parser("ingest")
    ing.add_argument("work")
    ing.add_argument("--allow-defects", action="store_true",
                     help="commit despite failed structure checks (recorded)")
    sub.add_parser("resolve").add_argument("citation")
    sub.add_parser("versions").add_argument("work")
    sub.add_parser("text").add_argument("id")
    sub.add_parser("status").add_argument("id")
    q = sub.add_parser("quote"); q.add_argument("id"); q.add_argument("text")
    sub.add_parser("search").add_argument("query")
    d = sub.add_parser("diff"); d.add_argument("a"); d.add_argument("b")
    sub.add_parser("mcp")
    sub.add_parser("keygen")
    vf = sub.add_parser("verify")
    vf.add_argument("expression")
    vf.add_argument("--require-trusted", action="store_true",
                    help="exit 1 unless the attestation is signed by a trusted key")
    sub.add_parser("check").add_argument("work")
    sub.add_parser("refs").add_argument("scope", nargs="?")
    dv = sub.add_parser("derive")
    dv.add_argument("id"); dv.add_argument("--kind", default="ocr-md")
    dv.add_argument("--producer", required=True)
    dv.add_argument("--source-sha256", required=True)
    sub.add_parser("derived").add_argument("id")
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
        _ensure_trusted_file()
        return
    con = db_open(args.db)
    if args.cmd == "ingest":
        ingest(con, args.work, allow_defects=args.allow_defects)
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
        elif args.cmd == "derive":
            out = q_derive(con, args.id, args.kind, args.producer,
                           args.source_sha256, sys.stdin.read())
        elif args.cmd == "derived":
            out = q_derived(con, args.id)
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
        if args.cmd == "verify" and (not out["ok"] or
                (args.require_trusted and not out["authenticated"])):
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
        print(f"{out['expression']}\n  fragments: {out['fragments_checked']}"
              f" checked, {len(out['fragment_mismatches'])} mismatched\n"
              f"  expression hash: {'ok' if out['expression_hash_ok'] else 'MISMATCH'}"
              f" (format {a['hash_format']})\n"
              f"  attestation: {a['trust']}")
        if out["fragment_mismatches"]:
            print("  mismatched: " + ", ".join(out["fragment_mismatches"]))
        if not out["ok"] or (args.require_trusted and not out["authenticated"]):
            sys.exit(1)
    elif args.cmd == "derive":
        print(f"stored {out['kind']} for {out['fragment']} ({out['stored']} chars)")
    elif args.cmd == "derived":
        for a in out["artifacts"]:
            print(f"NON-CANONICAL DERIVED ARTIFACT - {a['kind']} by {a['producer']}")
            print(f"derived from image sha256:{a['source_sha256']} at {a['created_at']}")
            print("verify against the anchored image before relying on values\n")
            print(a["content"])
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
