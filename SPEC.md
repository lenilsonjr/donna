# donna - design page

donna is the law layer: a versioned, hash-anchored corpus of legal texts with a
resolver, a quote verifier, and (later) a change feed. It serves deterministic
answers about what the law says; it never interprets. Agents (mike) consume it;
donna contains no LLM in any serving path.

This page is current truth and mutates as truth changes. Decisions that need a
record get an ADR under `adr/` once the project has reviewers.

## Terminology

| Term | Definition | Never say |
|------|------------|-----------|
| donna | The corpus service: ingestion, storage, resolution, verification. | "the database", "the scraper" |
| Work | An abstract legal act with an identity across versions (FRBR). Example: `ie/2018/act/7`. | "document" |
| Expression | A Work at a version, in a language. Example: `ie/2018/act/7@enacted:en`. | "revision", "copy" |
| Manifestation | A serialization of an Expression (XML, HTML, PDF) at the source. | "format" (alone) |
| Fragment | The addressable unit inside an Expression: a section or schedule. Example: `…#sec-42`. | "paragraph", "chunk" |
| Adapter | Per-jurisdiction code that turns a source Manifestation into Work metadata + Fragments. | "crawler" |
| Tier | Adapter trust class. A: structured API/XML, deterministic. B: HTML scraping, deterministic. C: PDF/OCR + LLM extraction, mechanically checked. | - |
| Attestation | The ingestion record: source URL, fetch time, raw-bytes hash, parser id, structure-check results. | "log entry" |
| Corpus | The distributable artifact: text + structure + versions + metadata. Embeddings are derived indexes over it, never part of it. | "the vectors" |

## Identifiers

Fragment ids are `{jurisdiction}/{year}/{type}/{number}@{version}:{lang}#{fragment}`,
aligned with ELI path conventions so `resolve` can round-trip official ELI URIs.
Content hashes are sha256 over canonical fragment text (NFC, entities mapped,
whitespace collapsed). An Expression's hash is sha256 over its ordered fragment
hashes.

## Verbs

| Verb | Contract |
|------|----------|
| `ingest <work-path>` | Fetch from the jurisdiction adapter, parse, check structure, store Work/Expression/Fragments + Attestation. Idempotent: re-ingest of unchanged source yields identical content hashes. |
| `resolve <citation>` | Citation string (ELI URI, id path, or human form like `s 42 DPA 2018`) → canonical id, or non-zero exit. |
| `text <id>` | Print canonical text of a Fragment or Expression. |
| `status <id>` | Print provenance: source URL, hashes, ingestion attestation, structure-check results. |
| `quote <fragment-id> <text>` | Exit 0 iff the text appears verbatim (typographic normalization only) in the fragment; else exit 1 and point at the nearest match. The claim-verification primitive. |
| `search <query>` | Ranked fragments via lexical FTS. |
| `diff <id> <id>` | Unified diff of two Fragments' canonical text. |

## v0 acceptance criteria (tracer bullet, Ireland)

- **AC1** `donna ingest ie/2018/act/7` MUST ingest the Data Protection Act 2018
  from the Irish Statute Book ELI XML manifestation using only Python stdlib and
  no credentials. Verification: run from a fresh clone.
- **AC2** Every Fragment MUST carry a sha256 content hash; the Expression MUST
  carry a hash over its ordered fragment hashes; ingestion MUST write an
  Attestation. Verification: `donna status` shows all three.
- **AC3** Structure checks MUST run at ingest: section numbering complete with
  gaps explicitly reported, no empty fragments, stripped footnote count
  recorded. Verification: checks appear in the Attestation.
- **AC4** `donna resolve "s 42 DPA 2018"` and the ELI URL form MUST return the
  same fragment id. Verification: both commands, same output.
- **AC5** `donna quote` on a verbatim sentence of s. 42 MUST exit 0; the same
  sentence with one word altered MUST exit 1 with a pointer to the nearest
  match. Verification: both invocations scripted.
- **AC6** `donna text` and `donna search` MUST work offline once ingested.
  Verification: run with networking unavailable.
- **AC7** Re-running ingest MUST reproduce identical Expression and Fragment
  hashes. Verification: ingest twice, compare `status` output.
- **AC8** This page MUST document the model and criteria; the repo MUST carry
  the work as commits. Verification: inspection.

## Open questions

- **Q1** Which signing scheme anchors Attestations? Branch A: none, hashes only
  (cost: trust rests on the serving host; default for v0). Branch B: minisign
  keypair per ingester (cheap, no infrastructure). Branch C: sigstore +
  transparency log (real quorum trust, heavy). Default if unanswered at M5
  build start: B.
- **Q2** How are embeddings served? Branch A: not at all, FTS only (default for
  v0). Branch B: published derived index with a model attestation (which model,
  which corpus hash). C: computed client-side by consumers. Default at M6: B.
- **Q3** How is the corpus distributed - git-tracked data files, GitHub
  release artifacts, or a fetchable API only?
- **Q4** What license does the project ship under?
- **Q5** Which organization/namespace publishes the repos?

## Milestones

Build order, each blocking the next. M1: v0 tracer bullet (this page). M2:
second Expression per Work (Law Reform Commission Revised Acts) plus `diff`
and `status` across versions. M3: Portugal adapter (DRE ELI, consolidated
regimes). M4: MCP server exposing the verbs. M5: attestation signing (Q1).
M6: derived embedding index (Q2). Later milestones are shells on purpose;
detail lands when a milestone unblocks.

## Suggested technical approach

NOT signed off.

Single-file `donna.py` CLI over SQLite, with FTS5 for search and an adapter
registry keyed by jurisdiction. The Ireland adapter reads the eISB
`legislation.dtd` XML: elements `part > sect > number/title/p`. Empty
punctuation elements (`emdash`, `odq`, `cdq`, `osq`, `csq`, `euro`) and Irish
fada elements map to characters; `fn` footnotes are stripped and counted. Canonicalization:
NFC, entity mapping, per-line whitespace collapse. `resolve` matches ELI
paths, eISB URLs, and short-title/acronym citation forms against Work
metadata.
