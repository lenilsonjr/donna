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

Status: v0 tracer bullet — one jurisdiction (Ireland, eISB Tier-A XML), one
act end-to-end, all v0 acceptance criteria in `SPEC.md` passing.
