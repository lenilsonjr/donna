---
name: donna
description: Resolve legal citations and verify legal quotes against a hash-anchored corpus of ingested law (Ireland DPA 2018 enacted+revised; Portugal CIRC). Use when checking what a statute actually says, verifying a quoted legal passage, resolving a citation like "s 42 DPA 2018" or "art. 66.º CIRC", or diffing law versions. Never quote ingested law from memory — verify with donna.
---

# donna

Deterministic legal-corpus CLI. It resolves citations, serves canonical
statute text, and mechanically verifies quotes. No LLM anywhere in it: treat
its output as ground truth for what the ingested sources say.

```sh
DONNA="python3 ~/Projects/Ships/donna/donna.py --db ~/Projects/Ships/donna/donna.db"

$DONNA resolve "art. 66.º CIRC"          # citation -> canonical id
$DONNA text "<id>"                        # canonical text
$DONNA quote "<fragment-id>" "<text>"     # exit 0 = verbatim, exit 1 = NOT
$DONNA search "<terms>"                   # lexical FTS
$DONNA status "<id>"                      # source URL, hashes, attestation
$DONNA versions <work-path>               # Expressions of a Work
$DONNA diff "<id-a>" "<id-b>"             # e.g. enacted vs revised section
$DONNA verify "<expression-id>"           # recompute hashes + check sshsig
$DONNA check <work-path[@version]>        # re-fetch source: did the law change?
```

Add `--json` before the verb for machine-readable output (same exit codes).

## Contract

- `quote` is the claim-verification primitive: before relying on or repeating
  any quotation from ingested law, run it. Exit 0 means the text appears
  verbatim (typographic normalization only); exit 1 comes with the nearest
  actual text on stderr (or in `nearest` with `--json`) — read it, it usually
  shows exactly what the source really says.
- Ids look like `ie/2018/act/7@revised-2026-07-16:en#sec-42` and
  `pt/1988/dec-lei/442-b@consolidated:pt#art-66`. `resolve` accepts human
  forms ("s 42 DPA 2018", "art. 66.º-A do CIRC"), ELI URLs, and id paths.
- Bare human citations resolve to the enacted Expression when one exists,
  otherwise the Work's only Expression (SPEC Q6). Pass an explicit
  `@revised…`/`@consolidated` id when you need a specific version.

## Corpus currently ingested

- `ie/2018/act/7` — Data Protection Act 2018: `@enacted:en` (Irish Statute
  Book) and `@revised-2026-07-16:en` (Law Reform Commission Revised Act).
- `pt/1988/dec-lei/442-b` — Código do IRC (CIRC), `@consolidated:pt` from
  Portal das Finanças; includes art. 66.º (CFC / imputação de rendimentos).

`versions <work>` confirms what is present. If a Work is missing, say so
rather than ingesting on your own initiative.

## Ingest etiquette

`ingest` and `check` fetch from government sources (the Portugal work makes
~170 polite requests over a couple of minutes); `ingest` also rewrites that
Expression's corpus rows. `check` exits 2 when content actually changed —
trust `content_changed`, not `source_changed` (pages churn cosmetically). Run it only when the user asks for a (re)ingest or clearly wants
a Work added, and never inside a tight loop. Everything else works offline.

## For non-shell hosts

`donna mcp` serves the read verbs (not ingest) as MCP tools over stdio.
