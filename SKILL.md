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
- **Portugal (tax, corporate)**: `pt/1988/dec-lei/442-b` Código do IRC /
  CIRC (`@consolidated:pt`) — art. 2.º (residência: sede ou direcção
  efectiva), art. 5.º (estabelecimento estável), art. 66.º (CFC).
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
  `pt/1987/dec-lei/78`; Estado de Sítio/Emergência `pt/1986/lei/44`;
  Regime Geral das Contra-Ordenações DL 433/82 `pt/1982/dec-lei/433`;
  Comissões de Dissuasão (procedure) DL 130-A/2001
  `pt/2001/dec-lei/130-a`; Lei do Tabaco Lei 37/2007 `pt/2007/lei/37`
  (all `@consolidated:pt`, PGDL). Not on PGDL, so not ingested: Decreto
  Regulamentar 61/94 (licit market / hemp cultivation).
- **Portugal (civil)**: Código Civil `pt/1966/dec-lei/47344` (2,382
  articles — 483/496 responsabilidade e danos, 1207–1230 empreitada);
  Código de Processo Civil `pt/2013/lei/41` (1,146 articles); Lei de Defesa
  do Consumidor `pt/1996/lei/24`; conformidade de bens DL 84/2021
  `pt/2021/dec-lei/84`; Julgados de Paz `pt/2001/lei/78` (all
  `@consolidated:pt`, PGDL). Unqualified citations resolve to the latest
  dated expression when a work carries re-ingest history.
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
- **US federal (contract pack)**: Title 9 Arbitration / Federal Arbitration
  Act `us/1947/usc/9` (ch. 2 = New York Convention, `#sec-201`…`#sec-208`);
  Title 17 Copyrights `us/1976/usc/17` (`#sec-101` "work made for hire"
  definition, `#sec-201`, `#sec-204`); Title 18 Crimes `us/1948/usc/18`
  (ch. 90 trade secrets / DTSA: `#sec-1833` whistleblower immunity,
  `#sec-1836`, `#sec-1839`). 2023 editions, GovInfo, `@consolidated:en`.
  Hyphenated sections resolve too: "15 USC 78dd-2" (FCPA, domestic concerns).
- **England & Wales / UK**: Arbitration Act 1996 `uk/1996/ukpga/23`
  (seat ss 2-3, stay s 9, substantive law s 46, challenges ss 67-69,
  enforcement s 66); Contracts (Rights of Third Parties) Act 1999
  `uk/1999/ukpga/31`; Late Payment of Commercial Debts (Interest) Act 1998
  `uk/1998/ukpga/20`; Unfair Contract Terms Act 1977 `uk/1977/ukpga/50`
  (ss 26-27: international-supply and choice-of-law carve-outs); Limitation
  Act 1980 `uk/1980/ukpga/58` (s 5: six years). All `@revised-<date>:en`
  from legislation.gov.uk CLML XML (Tier A). Pattern adapter: any
  `uk/<year>/ukpga/<n>[@revised|@enacted]` ingests. Resolve accepts
  "s 9 Arbitration Act 1996", "s 5A …", "s 26 UCTA 1977", and
  legislation.gov.uk section URLs. Repealed sections (e.g. UCTA s 30,
  Limitation Act s 34) are legitimately empty fragments.
- **EU**: GDPR `eu/2016/reg/679` (`@consolidated:en`, the 2016-05-04
  consolidation with the 2018 corrigendum; EUR-Lex ELI HTML, Tier B).
  Resolve accepts "art. 28 GDPR", "Article 82 of Regulation (EU) 2016/679",
  EUR-Lex ELI URLs. EUR-Lex answers HTTP 202 with an empty body while it
  renders a page - the adapter says so; wait and retry the ingest.
- **Delaware**: Title 6 ch. 27 Contracts `de/1953/title/6` (`#sec-2708`
  choice of law, the $100,000 floor) and Title 10 ch. 57 Uniform Arbitration
  Act `de/1953/title/10` (`@consolidated:en`, delcode.delaware.gov, Tier B).
  **Coverage is partial by design** - only the chapters listed in the
  registry; `status` shows `"coverage": "partial"` and the chapter list.
  Resolve accepts "6 Del. C. § 2708".
- **Portugal (tax, personal)**: Código do IRS / CIRS `pt/1988/dec-lei/442-a`
  (`@consolidated:pt`, Portal das Finanças) - the personal-income side of
  the CIRC pair, incl. the individual CFC imputation rule.

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
