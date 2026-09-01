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
$DONNA refs [scope-prefix]                # discovery: cited-but-not-ingested acts
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

- **Ireland**: `ie/2018/act/7` Data Protection Act 2018 (`@enacted:en` and
  `@revised-2026-07-16:en`).
- **Portugal (tax)**: `pt/1988/dec-lei/442-b` Código do IRC / CIRC
  (`@consolidated:pt`) — includes art. 66.º (CFC).
- **Portugal (general)**: Código da Estrada `pt/1994/dec-lei/114`; Lei das
  Armas `pt/2006/lei/5` (+ weapons annex); droga DL 15/93
  `pt/1993/dec-lei/15` **including the substance schedules as annex
  fragments** (`#anexo-tabela-i-c` holds cannabis — the statutory spelling
  is "Canabis", unaccented); descriminalização Lei 30/2000
  `pt/2000/lei/30`; Portaria 94/96 `pt/1996/portaria/94` (limites
  quantitativos — its Mapa is a scanned image, anchored as
  `#anexo-mapa` with the image's sha256, not yet transcribed); medical cannabis Lei 33/2018 `pt/2018/lei/33` + DL
  8/2019 `pt/2019/dec-lei/8`; Lei de Segurança Interna `pt/2008/lei/53`;
  Código Penal `pt/1982/dec-lei/400`; Código de Processo Penal
  `pt/1987/dec-lei/78`; Estado de Sítio/Emergência `pt/1986/lei/44`
  (all `@consolidated:pt`, PGDL).
- **Brazil (elections)**: Código Eleitoral `br/1965/lei/4737`; Lei das
  Eleições `br/1997/lei/9504` (doações: art. 23); Lei dos Partidos
  `br/1995/lei/9096` (all `@consolidated:pt-BR`, Planalto).
- **US federal**: Internal Revenue Code `us/1986/usc/26` (1,875 sections)
  and Title 15 Commerce and Trade `us/1926/usc/15` (2,434 sections — Sherman
  Act at `#sec-1`), 2023 editions via GovInfo (`@consolidated:en`); resolve
  accepts "26 USC 951A" / "15 USC 1" / "IRC § 7701".
- **Wyoming**: Title 17 (corporations; ch. 29 = LLC Act)
  `wy/1977/title/17`; Title 34.1 (UCC) `wy/1977/title/34-1`
  (`@consolidated:en`); resolve accepts "W.S. 17-29-201".

No case law anywhere, by explicit scope decision. `versions <work>` confirms
what is present. If a Work is missing, say so rather than ingesting on your
own initiative.

## Ingest etiquette

`ingest` and `check` fetch from government sources (the Portugal work makes
~170 polite requests over a couple of minutes); `ingest` also rewrites that
Expression's corpus rows. `check` exits 2 when content actually changed —
trust `content_changed`, not `source_changed` (pages churn cosmetically). Run it only when the user asks for a (re)ingest or clearly wants
a Work added, and never inside a tight loop. Everything else works offline.

## For non-shell hosts

`donna mcp` serves the read verbs (not ingest) as MCP tools over stdio.
