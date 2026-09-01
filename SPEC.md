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
| `versions <work-path>` | List every Expression of a Work: version, content hash, ingest time, source. |
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

## M2 acceptance criteria (second Expression, revised Ireland)

- **AC9** `donna ingest ie/2018/act/7@revised` MUST ingest the Law Reform
  Commission Revised Act XML as a second Expression of the same Work, with the
  revision date parsed from the source in the Expression id
  (`@revised-YYYY-MM-DD:en`). Verification: `donna versions ie/2018/act/7`
  lists both Expressions.
- **AC10** Canonical fragment text MUST exclude the LRC editorial apparatus
  (`div.annotations`); the stripped annotation count MUST be recorded in the
  Attestation. Verification: attestation checks and `text` output.
- **AC11** `donna diff` between the enacted and revised Expression of an
  amended section MUST show the amendment without whitespace-only noise.
  Verification: diff of a section amended since 2018.
- **AC12** Sections present only in the revised Expression (inserted, lettered)
  MUST appear as Fragments. Verification: fragment ids present in the revised
  Expression and absent from the enacted one.

The LRC's amendment markers and annotation blocks ride on editorial elements
(`fn`, `marker`, `div.annotations`); the adapter strips them all, so canonical
revised text is clean consolidated law. Stripped counts are recorded in the
Attestation.

## M3 acceptance criteria (Portugal, second jurisdiction)

- **AC13** `donna ingest pt/1988/dec-lei/442-b@consolidated` MUST ingest the
  CIRC (Código do IRC) from Portal das Finanças as Expression
  `@consolidated:pt`: index-driven, one fetched page per article, Tier B
  recorded in the Attestation together with the page count. Verification:
  ingest output and `donna status`.
- **AC14** `donna resolve "art. 66.º CIRC"` MUST return the art. 66.º fragment
  id, handling Portuguese citation forms, the ordinal marker and work aliases.
  Verification: resolve output.
- **AC15** `donna quote` MUST verify a verbatim passage of art. 66.º and
  reject a tampered variant, exercising Portuguese text and accents.
  Verification: both invocations.

Tier B works are configured, not discovered: the adapter carries a source map
per Work (index URL, page slug, title, aliases). The tax authority's gray
redaction attributions (`em` elements, "Redação da Lei n.º …") are editorial
and are stripped and counted; statutory status text such as "(Revogado.)"
stays.

## M4 acceptance criteria (agent surfaces)

- **AC16** Every read verb (resolve, versions, text, status, quote, search,
  diff) MUST accept `--json` and emit machine-readable JSON; `quote` MUST
  keep its exit-code contract in both modes. Verification: each verb run with
  `--json` and parsed.
- **AC17** `donna mcp` MUST serve the read verbs as MCP tools over stdio
  (newline-delimited JSON-RPC 2.0: initialize, tools/list, tools/call),
  stdlib only and read-only - `ingest` stays CLI-only by design.
  Verification: scripted JSON-RPC session exercising initialize, tools/list,
  and donna_quote for a verified quote, a tampered quote, and an unknown
  fragment (isError).
- **AC18** The repo MUST carry a SKILL.md that teaches a shell-capable
  harness to drive the CLI: corpus contents, verb contract, ingest etiquette.
  Verification: inspection; a symlink into `~/.claude/skills` makes it live.

## M5 acceptance criteria (attestation signing)

- **AC19** `donna keygen` MUST create an Ed25519 ingester keypair (OpenSSH
  format, mode 0600) at `.donna/ingester_key`, refusing to overwrite an
  existing one. Verification: run twice, inspect.
- **AC20** ingest MUST store a canonical attestation payload (expression id,
  source URL, fetch time, raw hash, expression hash, parser, checks) and,
  when the ingester key exists, an sshsig signature over it plus the signer
  public key. Ingest without a key MUST still work and record the attestation
  as unsigned. Verification: `donna status` shows the signed state; the
  attestation row carries payload and signature.
- **AC21** `donna verify <expression-id>` MUST recompute every fragment hash
  and the expression hash from the stored corpus, compare them to the
  recorded values, and check the attestation signature; any mismatch MUST
  exit 1 naming the failing fragment or check. The MCP server MUST expose it
  as donna_verify. Verification: clean pass on the real corpus; a corrupted
  fragment row in a scratch copy fails; a tampered payload fails signature
  verification.

## M7 acceptance criteria (change detection)

- **AC22** `donna check <work-path[@version]>` MUST re-acquire the source
  without writing anything, and report `source_changed` (raw bytes hash vs
  the latest attestation) and `content_changed` (recomputed expression hash
  vs the stored Expression) separately - cosmetic page churn must not read
  as a law change. Exit 0 when content is unchanged, 2 when it changed, 1 on
  error. Verification: run against all three Expressions; the Portal das
  Finanças pages demonstrate cosmetic churn (footer date) with content
  unchanged.
- **AC23** The CLI form MUST honor `--json` and the MCP server MUST expose
  donna_check. Verification: parsed JSON output and a scripted MCP call.

## Open questions

- **Q1** ANSWERED at M5 build start (2026-09-01): sshsig - `ssh-keygen -Y`
  signatures with an Ed25519 ingester key, namespace `donna-attestation`.
  Same cryptography as branch B (minisign) through a tool every target
  machine already ships, keeping the no-dependency rule; verifiable with
  stock OpenSSH >= 8.1. Branch C (sigstore + transparency log) remains the
  upgrade path for quorum trust.
- **Q2** How are embeddings served? Branch A: not at all, FTS only (default for
  v0). Branch B: published derived index with a model attestation (which model,
  which corpus hash). C: computed client-side by consumers. Default at M6: B.
  M6 blocked pending an answer (2026-09-01): branch B needs an embedding
  model, and the build machine has no local runtime (no ollama) - so the
  choice is donna's first dependency (local model) or an API key and per-call
  cost (hosted embeddings). Owner decision.
- **Q3** How is the corpus distributed - git-tracked data files, GitHub
  release artifacts, or a fetchable API only?
- **Q4** What license does the project ship under?
- **Q5** Which organization/namespace publishes the repos?
- **Q6** Which Expression does a human citation resolve to when a Work has
  several - most current, or enacted? Interim rule: enacted when present,
  otherwise the Work's only Expression; revisit at M4.

## Milestones

Build order, each blocking the next. M1: v0 tracer bullet (this page). M2:
second Expression per Work (Law Reform Commission Revised Acts) plus `diff`
and `status` across versions. M3: Portugal adapter (DRE ELI target; v0 ships Portal das Finanças). M4:
agent surfaces - `--json` on read verbs, a stdio MCP shim over the same
functions (read-only), and a SKILL.md for shell-capable harnesses; the CLI
stays canonical and MCP is a distribution format, not the architecture.
M5: attestation signing (Q1).
M6: derived embedding index (Q2; blocked pending the Q2 answer). M7: change
feed - `donna check` re-acquires an Expression's source without writing and
reports source-level vs content-level change against the stored corpus; the
seed of watch/subscriptions. M7 proceeds while M6 awaits Q2. Later
milestones are shells on purpose; detail lands when a milestone unblocks.

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
