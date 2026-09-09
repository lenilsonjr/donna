"""Regression suite for LAB-25 audit findings. No network: a fixture adapter
stands in for real sources; signing uses temporary keys in isolated dirs.

Run: python3 -m unittest discover -s tests
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import donna  # noqa: E402

FX = ("fx", "2000", "act", "1")

def fx_result(cfg, version):
    frags = [dict(f) for f in cfg["frags"]]
    return {"work_meta": {"title": cfg.get("title", "Fixture Act 2000"),
                          "aliases": cfg.get("aliases", "FXA")},
            "fragments": frags, "label": cfg.get("label", "consolidated"),
            "lang": "en", "source_url": cfg.get("source_url", "fixture://act1"),
            "raw": cfg.get("raw", b"fixture-raw"),
            "checks": dict(cfg.get("checks", {"tier": "T", "unparsed_pages": [],
                                              "toc_missing": [],
                                              "empty_fragments": []})),
            "parser": "donna-fx/1"}

BASE_FRAGS = [
    {"kind": "section", "number": "1", "heading": "Short title",
     "text": "This Act may be cited as the Fixture Act 2000."},
    {"kind": "section", "number": "2", "heading": "Cross-border matters",
     "text": "Cross-border co-operation shall respect the twenty-five"
             " per cent threshold."},
]

class DonnaCase(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp(prefix="donna-test-")
        self.db = os.path.join(self.td, "test.db")
        donna.KEY_DIR = os.path.join(self.td, ".donna")
        os.makedirs(donna.KEY_DIR)
        key = os.path.join(donna.KEY_DIR, "ingester_key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", key, "-N", "",
                        "-C", "donna-ingester", "-q"], check=True)
        donna._ensure_trusted_file()
        self.cfg = {"source": fx_result, "frags": [dict(f) for f in BASE_FRAGS]}
        donna.WORKS[FX] = self.cfg
        self.con = donna.db_open(self.db)

    def tearDown(self):
        self.con.close()
        donna.WORKS.pop(FX, None)
        shutil.rmtree(self.td, ignore_errors=True)

    def ingest(self, allow_defects=False):
        donna.ingest(self.con, "fx/2000/act/1", allow_defects=allow_defects)

    def expr_ids(self):
        return [r[0] for r in self.con.execute(
            "SELECT id FROM expressions ORDER BY id")]


class TestF1TrustedSigners(DonnaCase):
    def test_forged_corpus_is_not_authenticated(self):
        self.ingest()
        expr = self.expr_ids()[0]
        # attacker: alter text, recompute hashes, re-sign with their own key
        atk_dir = tempfile.mkdtemp(prefix="donna-attacker-")
        atk_key = os.path.join(atk_dir, "ingester_key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", atk_key, "-N", "",
                        "-C", "donna-ingester", "-q"], check=True)
        rows = self.con.execute("SELECT id, kind, number, heading, text FROM"
                                " fragments WHERE expression_id = ?"
                                " ORDER BY ord", (expr,)).fetchall()
        doctored = [{"kind": k, "number": n, "heading": h,
                     "text": t.replace("twenty-five", "ten")}
                    for _, k, n, h, t in rows]
        fh, mh = donna._expression_hashes(doctored)
        with self.con:
            for (fid, _, _, _, _), d, h in zip(rows, doctored, fh):
                self.con.execute("UPDATE fragments SET text = ?, content_hash"
                                 " = ? WHERE id = ?", (d["text"], h, fid))
            self.con.execute("UPDATE expressions SET content_hash = ? WHERE"
                             " id = ?", (mh, expr))
            pay_row = self.con.execute("SELECT payload_json FROM attestations"
                                       " WHERE expression_id = ?",
                                       (expr,)).fetchone()
            payload = json.loads(pay_row[0])
            payload["content_hash"] = mh
            new_payload = json.dumps(payload, sort_keys=True,
                                     separators=(",", ":"), ensure_ascii=False)
            real_key_dir = donna.KEY_DIR
            donna.KEY_DIR = atk_dir
            sig, signer = donna.sign_payload(new_payload.encode())
            donna.KEY_DIR = real_key_dir
            self.con.execute("UPDATE attestations SET payload_json = ?,"
                             " signature = ?, signer = ? WHERE"
                             " expression_id = ?",
                             (new_payload, sig, signer, expr))
        out = donna.q_verify(self.con, expr)
        self.assertFalse(out["authenticated"])
        self.assertEqual(out["attestation"]["trust"], "signed-untrusted")
        shutil.rmtree(atk_dir, ignore_errors=True)

    def test_unsigned_is_distinguishable(self):
        self.ingest()
        expr = self.expr_ids()[0]
        with self.con:
            self.con.execute("UPDATE attestations SET signature = NULL WHERE"
                             " expression_id = ?", (expr,))
        out = donna.q_verify(self.con, expr)
        self.assertFalse(out["authenticated"])
        self.assertEqual(out["attestation"]["trust"], "unsigned")

    def test_genuine_corpus_authenticates(self):
        self.ingest()
        out = donna.q_verify(self.con, self.expr_ids()[0])
        self.assertTrue(out["ok"])
        self.assertTrue(out["authenticated"])
        self.assertEqual(out["attestation"]["trust"], "signed-trusted")


class TestF2IdentityBinding(DonnaCase):
    def test_renamed_fragment_fails_verification(self):
        self.ingest()
        expr = self.expr_ids()[0]
        with self.con:
            self.con.execute("UPDATE fragments SET number = '999999' WHERE"
                             " number = '2' AND expression_id = ?", (expr,))
        out = donna.q_verify(self.con, expr)
        self.assertFalse(out["expression_hash_ok"])
        self.assertFalse(out["ok"])

    def test_heading_change_fails_verification(self):
        self.ingest()
        expr = self.expr_ids()[0]
        with self.con:
            self.con.execute("UPDATE fragments SET heading = 'Doctored' WHERE"
                             " number = '1' AND expression_id = ?", (expr,))
        out = donna.q_verify(self.con, expr)
        self.assertFalse(out["ok"])

    def test_provenance_change_fails_verification(self):
        self.ingest()
        expr = self.expr_ids()[0]
        with self.con:
            self.con.execute("UPDATE expressions SET source_url = 'evil://'"
                             " WHERE id = ?", (expr,))
        out = donna.q_verify(self.con, expr)
        self.assertFalse(out["attestation"]["payload_matches_corpus"])
        self.assertFalse(out["ok"])


class TestF3IngestGate(DonnaCase):
    def test_zero_fragments_cannot_overwrite(self):
        self.ingest()
        before = self.con.execute("SELECT COUNT(*) FROM fragments").fetchone()[0]
        self.cfg["frags"] = []
        with self.assertRaises(SystemExit):
            self.ingest()
        after = self.con.execute("SELECT COUNT(*) FROM fragments").fetchone()[0]
        self.assertEqual(before, after)

    def test_unparsed_pages_block(self):
        self.ingest()
        self.cfg["checks"] = {"tier": "T", "unparsed_pages": ["2"],
                              "toc_missing": [], "empty_fragments": []}
        self.cfg["frags"] = [dict(BASE_FRAGS[0])]
        with self.assertRaises(SystemExit):
            self.ingest()
        # original text intact
        row = self.con.execute("SELECT text FROM fragments WHERE number = '2'"
                               ).fetchone()
        self.assertIn("twenty-five", row[0])

    def test_allow_defects_overrides_and_records(self):
        self.cfg["checks"] = {"tier": "T", "unparsed_pages": ["9"],
                              "toc_missing": [], "empty_fragments": []}
        self.ingest(allow_defects=True)
        checks = json.loads(self.con.execute(
            "SELECT checks_json FROM attestations").fetchone()[0])
        self.assertIn("gate_overridden", checks)


class TestF4ImmutableVersions(DonnaCase):
    def test_changed_content_gets_new_id_and_history_survives(self):
        self.ingest()
        first = self.expr_ids()[0]
        original = self.con.execute("SELECT text FROM fragments WHERE"
                                    " expression_id = ? AND number = '2'",
                                    (first,)).fetchone()[0]
        self.cfg["frags"] = [dict(BASE_FRAGS[0]),
                             dict(BASE_FRAGS[1], text="Amended text.")]
        self.ingest()
        ids = self.expr_ids()
        self.assertEqual(len(ids), 2)
        still = self.con.execute("SELECT text FROM fragments WHERE"
                                 " expression_id = ? AND number = '2'",
                                 (first,)).fetchone()[0]
        self.assertEqual(original, still)
        latest = donna.expression_for(self.con, "fx/2000/act/1", "consolidated")
        self.assertNotEqual(latest, first)
        new_text = self.con.execute("SELECT text FROM fragments WHERE"
                                    " expression_id = ? AND number = '2'",
                                    (latest,)).fetchone()[0]
        self.assertEqual(new_text, "Amended text.")

    def test_unchanged_reingest_is_idempotent(self):
        self.ingest()
        self.ingest()
        self.assertEqual(len(self.expr_ids()), 1)


class TestF5ExplicitVersions(DonnaCase):
    def test_explicit_version_does_not_fall_back(self):
        self.ingest()  # only @consolidated exists
        with self.assertRaises(donna.DonnaError):
            donna.q_resolve(self.con, "fx/2000/act/1@enacted:en#sec-1")

    def test_uk_enacted_url_does_not_serve_revised(self):
        with self.con:
            self.con.execute("INSERT INTO works VALUES (?,?,?,?,?,?,?)",
                             ("uk/1996/ukpga/23", "uk", "ukpga", 1996, "23",
                              "Arbitration Act 1996", ""))
            self.con.execute("INSERT INTO expressions VALUES (?,?,?,?,?,?,?)",
                             ("uk/1996/ukpga/23@revised-2025-08-01:en",
                              "uk/1996/ukpga/23", "revised-2025-08-01", "en",
                              "fixture://", "x", "now"))
        with self.assertRaises(donna.DonnaError):
            donna.q_resolve(self.con, "https://www.legislation.gov.uk/ukpga/"
                                      "1996/23/section/9/enacted")
        with self.assertRaises(donna.DonnaError):
            donna.q_resolve(self.con, "https://www.legislation.gov.uk/ukpga/"
                                      "1996/23/section/9/2000-01-01")

    def test_pt_structured_citation_survives_dated_history(self):
        with self.con:
            self.con.execute("INSERT INTO works VALUES (?,?,?,?,?,?,?)",
                             ("pt/2099/dec-lei/9", "pt", "dec-lei", 2099, "9",
                              "Fixture Decreto", ""))
            for ver in ("consolidated", "consolidated-2099-01-02"):
                self.con.execute("INSERT INTO expressions VALUES (?,?,?,?,?,?,?)",
                                 (f"pt/2099/dec-lei/9@{ver}:pt",
                                  "pt/2099/dec-lei/9", ver, "pt",
                                  "fixture://", "x", "now"))
        out = donna.q_resolve(self.con, "DL 9/2099")
        self.assertEqual(out["id"],
                         "pt/2099/dec-lei/9@consolidated-2099-01-02:pt")

    def test_unqualified_citation_keeps_fallback(self):
        self.ingest()
        out = donna.q_resolve(self.con, "s 1 Fixture Act 2000")
        self.assertTrue(out["id"].endswith("#sec-1"))


class TestF6ResolveValidation(DonnaCase):
    def test_nonexistent_canonical_id_fails(self):
        self.ingest()
        with self.assertRaises(donna.DonnaError):
            donna.q_resolve(self.con, "xx/9999/act/999@enacted:en#sec-1")

    def test_nonexistent_fragment_fails(self):
        self.ingest()
        expr = self.expr_ids()[0]
        with self.assertRaises(donna.DonnaError):
            donna.q_resolve(self.con, expr + "#sec-777")

    def test_shorthand_expands_to_concrete_id(self):
        self.ingest()
        out = donna.q_resolve(self.con, "fx/2000/act/1@consolidated")
        self.assertIn("@consolidated", out["id"])
        self.assertIn(out["id"], self.expr_ids())


class TestF7SearchRobustness(DonnaCase):
    def test_hyphenated_term_searches(self):
        self.ingest()
        out = donna.q_search(self.con, "cross-border")
        self.assertTrue(any("sec-2" in r["id"] for r in out["results"]))

    def test_unclosed_quote_never_escapes_as_sqlite_error(self):
        self.ingest()
        try:
            out = donna.q_search(self.con, '"unclosed')
            self.assertIn("results", out)  # sanitizer recovered it
        except donna.DonnaError:
            pass  # a structured failure is also acceptable
        except sqlite3.OperationalError:
            self.fail("OperationalError escaped q_search")

    def test_mcp_survives_bad_search_then_ping(self):
        self.ingest()
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "donna_search",
                        "arguments": {"query": '"unclosed'}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "donna_search",
                        "arguments": {"query": "cross-border"}}},
            {"jsonrpc": "2.0", "id": 4, "method": "ping"},
        ]
        p = subprocess.run(
            [sys.executable, os.path.join(root, "donna.py"),
             "--db", self.db, "mcp"],
            input="\n".join(json.dumps(m) for m in msgs) + "\n",
            capture_output=True, text=True, timeout=60)
        replies = {json.loads(l).get("id") for l in p.stdout.splitlines()}
        self.assertEqual(replies, {1, 2, 3, 4})


class TestF8EmptyQuote(DonnaCase):
    def test_empty_and_whitespace_quotes_fail(self):
        self.ingest()
        fid = self.expr_ids()[0] + "#sec-1"
        for bad in ("", "   ", "  ", "\n\t"):
            with self.assertRaises(donna.DonnaError):
                donna.q_quote(self.con, fid, bad)

    def test_real_quote_still_verifies(self):
        self.ingest()
        fid = self.expr_ids()[0] + "#sec-1"
        out = donna.q_quote(self.con, fid, "cited as the Fixture Act 2000")
        self.assertTrue(out["verified"])


if __name__ == "__main__":
    unittest.main()
