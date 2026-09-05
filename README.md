# donna

Donna knows everything.

**The law layer for agentic legal work.** A versioned, hash-anchored corpus
of legal texts with a citation resolver, a quote verifier, and a change
detector. Deterministic by design: there is no LLM in any serving path.
Agents make claims about the law; donna makes those claims checkable.

```sh
$ python3 donna.py ingest ie/2018/act/7
$ python3 donna.py resolve "s 42 DPA 2018"
ie/2018/act/7@enacted:en#sec-42

$ python3 donna.py quote "ie/2018/act/7@enacted:en#sec-42" \
    "shall respect the principle of data minimisation"
VERIFIED: quote appears verbatim in ie/2018/act/7@enacted:en#sec-42
```

Change one word of that quote and the exit code flips. Quote a repealed
threshold and the error shows what the law says now:

```sh
$ python3 donna.py quote "pt/1988/dec-lei/442-b@consolidated:pt#art-66" \
    "pelo menos 10% das partes de capital"
NOT VERIFIED: quote not found
nearest text: pelo menos 25% das partes de capital,
```

That primitive, cheap and mechanical and source-anchored, is the point.
LLMs hallucinate citations; a corpus with content hashes does not.

## Why

Legal AI fails in a specific way: the citation does not exist, the article
was revoked, the quoted text is subtly wrong. Those are not judgment errors.
They are lookup errors, and lookups can be checked by machine. donna is the
checking machine: ingest the law from official sources, fragment it into
addressable units, hash everything, sign the ingestion, and expose verbs an
agent can call before it relies on a quotation. The unverifiable residue of
legal work (interpretation, strategy, risk) stays with humans and smarter
systems built on top. donna keeps them honest about what the text says.

## Verbs

| Verb | What it does |
|---|---|
| `ingest <work>[@version]` | Fetch from the jurisdiction adapter, fragment, hash, sign, store |
| `resolve <citation>` | "art. 66.º CIRC", "26 USC 951A", "s 9 Arbitration Act 1996", ELI URLs → canonical id |
| `text <id>` | Canonical text of a fragment or a whole Expression |
| `quote <fragment-id> <text>` | Exit 0 iff verbatim (typographic tolerance only); otherwise the nearest real text |
| `search <query>` | Full-text search across the corpus |
| `diff <id> <id>` | Real amendment history, e.g. a section enacted vs revised |
| `status <id>` | Provenance: source URL, hashes, signed attestation, structure checks |
| `verify <expression>` | Recompute every hash from the stored corpus, check the sshsig signature |
| `check <work>` | Re-fetch the source: did the law actually change, or just the page? |
| `refs [scope]` | Discovery: acts the corpus cites but does not contain, ranked |
| `versions <work>` | Every ingested Expression of a Work |
| `derived <fragment-id>` | Marked non-canonical artifacts (e.g. a transcription of a scanned annex) |

Three surfaces, one set of functions: the CLI is canonical, `--json` makes
every read verb machine-readable with the same exit codes, and `donna mcp`
serves the read verbs as MCP tools over stdio for hosts without a shell.
`ingest` stays CLI-only on purpose. `SKILL.md` teaches shell-capable agents
the contract; its first rule is *never quote ingested law from memory*.

## Trust model

- **Identity**: FRBR Works, Expressions and Fragments with ELI-aligned ids,
  like `pt/1993/dec-lei/15@consolidated:pt#anexo-tabela-i-c`.
- **Integrity**: sha256 per fragment, an expression hash over the ordered
  fragment hashes, and a raw-bytes hash of everything fetched.
- **Provenance**: every ingest writes an attestation (source URL, fetch
  time, parser id, structure-check results) and signs it with an Ed25519
  ingester key via `ssh-keygen -Y`. Trust roots live in a
  `trusted_signers` file outside the corpus: `donna verify` reports
  unsigned, signed-untrusted or signed-trusted, and `--require-trusted`
  makes authentication mandatory. The signed manifest binds every
  fragment's identity, heading, order and text hash, so a tampered or
  renamed fragment is named exactly and a re-signed forgery is not
  authenticated.
- **Honest extraction**: adapters are tiered. A: structured XML/APIs
  (Irish Statute Book, Law Reform Commission, legislation.gov.uk CLML).
  B: HTML scraping with structure checks (Portal das Finanças, PGDL,
  Planalto, GovInfo, EUR-Lex, Delaware Code). C: PDF extraction
  (Wyoming LSO, via pdftotext). The tier is recorded in the attestation.
  Scanned annexes are anchored as image bytes with their hash; any LLM
  transcription of them lives in a separate `derived` table behind a
  non-canonical banner, never in the corpus.
- **Change detection**: `check` separates `content_changed` (canonical
  hashes moved: the law changed) from `source_changed` (raw bytes moved:
  the page churned). Government pages churn daily; the law mostly does not.

## What it can hold today

Adapters and configured Works cover eight jurisdictions: **Ireland** (any
act, enacted and LRC-revised), **UK** (any ukpga act, enacted and revised),
**Portugal** (tax codes from Portal das Finanças; general law from PGDL,
including the drug schedules as annex fragments), **Brazil** (Planalto
consolidations), **US federal** (any USC title via GovInfo), **Wyoming**
(LSO statute PDFs), **Delaware** (declared partial coverage by chapter) and
the **EU** (EUR-Lex ELI). The corpus this repo's authors run holds 33
Expressions and about 11,000 fragments: data protection, tax (CIRC, CIRS,
the IRC), elections, drugs, arms, traffic, criminal law and procedure,
arbitration, copyright, trade secrets, the GDPR and the Wyoming LLC Act.

The SQLite corpus is not tracked in git; verified snapshots are published
under [Releases](../../releases) with sha256 checksums, gzipped, after a
full hash-and-signature sweep. Download one and place it next to `donna.py`
as `donna.db`, or run `donna keygen` and `ingest` your own; every Work
above is one command. Embeddings (search is FTS for now) and the license
are open questions in `SPEC.md`.

## Not legal advice

donna verifies what sources say, not what the law means. Sources differ in
authority: some are official gazettes, some are government consolidations
without legal force, one is a prosecutor's office reference site. `status`
names the source for every Expression; read it before you rely on one.
Nothing here is legal advice, and no case law is included by design.

## Design notes

Single-file Python, stdlib only, ~1,900 lines, with a no-network
regression suite under `tests/`. SQLite with FTS5. The spec
(`SPEC.md`) carries the terminology, the acceptance criteria per milestone
(all passing), and the open questions with priced options. The name is from
Suits: donna is the one who knows where everything is and never guesses.
