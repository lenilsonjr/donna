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
trust chain) and the roadmap (Revised Acts diffing, Portugal DRE adapter, MCP
server, attestation signing).

Status: M3 - two jurisdictions, three Expressions. Ireland: DPA 2018 enacted
(eISB) and revised (Law Reform Commission), both Tier-A XML; `donna diff`
shows real amendment history and the same quote verifies against revised
while failing against enacted. Portugal: the CIRC (Código do IRC) from Portal
das Finanças, Tier B, 171 articles, index-driven with one page per article;
`donna resolve "art. 66.º CIRC"` lands on the CFC article and quote
verification catches a tampered ownership threshold. All acceptance criteria
in `SPEC.md` passing.
