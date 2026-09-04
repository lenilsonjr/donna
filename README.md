# donna

Donna knows everything.

The law layer for agentic legal work: a versioned, hash-anchored corpus of
legal texts with a citation resolver and a quote verifier. Deterministic — no
LLM in any serving path. Agents build claims on top; donna makes the claims
checkable.

```sh
python3 donna.py ingest ie/2018/act/7
python3 donna.py resolve "s 42 DPA 2018"
# ie/2018/act/7@enacted:en#sec-42
python3 donna.py quote "ie/2018/act/7@enacted:en#sec-42" \
  "shall respect the principle of data minimisation"
# VERIFIED: quote appears verbatim in ie/2018/act/7@enacted:en#sec-42
```

Change one word of that quote and the exit code tells an agent its citation is
wrong. That primitive — cheap, mechanical, source-anchored — is the point.

Python stdlib only. Corpus lives in SQLite next to the CLI. See `SPEC.md` for
the model (FRBR Works/Expressions/Fragments, ELI-aligned ids, adapter tiers,
trust chain) and the roadmap.

Three surfaces, one set of verbs: the CLI is canonical (agents with a shell
drive it directly; `SKILL.md` teaches them how), `--json` makes every read
verb machine-readable, and `donna mcp` serves the read verbs as MCP tools
over stdio for hosts without a shell. `ingest` stays CLI-only by design.

Status: M10 - eight jurisdictions (IE, PT, BR, US federal, Wyoming, UK,
EU, Delaware), 33 Expressions, ~11,150 fragments, three agent surfaces,
signed attestations. M10 added the contract-law pack a real cross-border
engagement needed: legislation.gov.uk (Tier A CLML, pattern adapter for any
UK act), EUR-Lex ELI (GDPR), the Delaware Code (partial coverage, declared),
US titles 9, 17 and 18, and the Portuguese CIRS - and fixed two silent
corpus defects on the way (GovInfo dash-encoded section numbers and a
Wyoming header filter that had dropped two-thirds of Title 17). Every ingest signs a canonical attestation payload with
an Ed25519 ingester key (sshsig, `ssh-keygen -Y`); `donna verify` recomputes
every hash from the stored corpus and checks the signature, so a tampered
fragment is named exactly and a doctored attestation fails verification.
`donna check` re-fetches a source and separates real legal change
(`content_changed`, canonical hashes) from cosmetic page churn
(`source_changed`, raw bytes) — the seed of the change feed. M6 (embeddings)
awaits the Q2 provider decision. Ireland: DPA 2018 enacted
(eISB) and revised (Law Reform Commission), both Tier-A XML; `donna diff`
shows real amendment history and the same quote verifies against revised
while failing against enacted. Portugal: the CIRC (Código do IRC) from Portal
das Finanças, Tier B, 171 articles, index-driven with one page per article;
`donna resolve "art. 66.º CIRC"` lands on the CFC article and quote
verification catches a tampered ownership threshold. All acceptance criteria
in `SPEC.md` passing.
