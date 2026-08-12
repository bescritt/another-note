#!/usr/bin/env python3
"""Full-coverage test suite for the monolithic another_note.py.

Uses stdlib unittest (PEP 668: no global pytest). Run:
    python3 test_another_note.py
Every public function in another_note.py is exercised here.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import another_note as A


class TestFNV(unittest.TestCase):
    def test_multiply_zero(self):
        self.assertEqual(A._fnv_multiply(0), 0)
    def test_multiply_known(self):
        # deterministic, just assert stability + 32-bit mask
        v = A._fnv_multiply(123456)
        self.assertEqual(v, v & A.MASK)
    def test_mix_zero(self):
        self.assertEqual(A._fnv_mix(0), 0)
    def test_fnv_deterministic(self):
        self.assertEqual(A.fnv_1a("facebook.com/example_page_one"),
                         A.fnv_1a("facebook.com/example_page_one"))
        self.assertNotEqual(A.fnv_1a("a"), A.fnv_1a("b"))
    def test_fnv_seed0(self):
        self.assertEqual(A.fnv_1a("x"), A.fnv_1a("x", 0))


class TestBloom(unittest.TestCase):
    def test_roundtrip(self):
        f, a = A.synthesize(["facebook.com/alice"], ["facebook.com/carol"]).values()
        self.assertEqual(A.classify("facebook.com/alice", f, a), A.FRIENDLY_NAME)
        self.assertEqual(A.classify("facebook.com/carol", f, a), A.AVERSE_NAME)
        self.assertEqual(A.classify("facebook.com/ghost", f, a), "neither")
        both = A.synthesize(["facebook.com/dup"], ["facebook.com/dup"])
        self.assertEqual(A.classify("facebook.com/dup", both[A.FRIENDLY_NAME], both[A.AVERSE_NAME]), "both")
    def test_from_to_bytes(self):
        f = A.BloomFilter.empty(1000, 20)
        f.add("x")
        self.assertTrue(f.test("x"))
        raw = f.to_bytes()
        g = A.BloomFilter.from_bytes(raw, 20)
        self.assertTrue(g.test("x"))
    def test_write_load_layout(self):
        f, a = A.synthesize(["facebook.com/x"], ["facebook.com/y"]).values()
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            A.write_filter(f, td / f"{A.FRIENDLY_NAME}.dat")
            A.write_filter(a, td / f"{A.AVERSE_NAME}.dat")
            f2, a2 = A.build_resolver(td)
            self.assertEqual(A.classify("facebook.com/x", f2, a2), A.FRIENDLY_NAME)
            self.assertEqual(A.classify("facebook.com/y", f2, a2), A.AVERSE_NAME)
            raw = (td / f"{A.FRIENDLY_NAME}.dat").read_bytes()
            self.assertEqual(len(raw[:A._SPLIT]), A._SPLIT)
    def test_youtube_aware(self):
        f, a = A.synthesize([], ["youtube.com/c/someone"]).values()
        self.assertEqual(A.classify_youtube_aware("youtube.com/@someone", f, a), A.AVERSE_NAME)
    def test_estimate_fill(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f, a = A.synthesize(["facebook.com/x"], []).values()
            A.write_filter(f, td / f"{A.FRIENDLY_NAME}.dat")
            A.write_filter(a, td / f"{A.AVERSE_NAME}.dat")
            est = A.estimate_fill_rate(td)
            self.assertIn(A.FRIENDLY_NAME, est)
            self.assertGreaterEqual(est[A.FRIENDLY_NAME]["fill_ratio"], 0.0)


class TestIdentifier(unittest.TestCase):
    def test_facebook(self):
        self.assertEqual(A.normalize_url("https://www.facebook.com/example_page_one"),
                         "facebook.com/example_page_one")
        self.assertEqual(A.normalize_url("https://facebook.com/profile.php?id=100"),
                         "facebook.com/100")
    def test_twitter_x(self):
        self.assertEqual(A.normalize_url("https://twitter.com/example_handle_one"),
                         "twitter.com/example_handle_one")
        self.assertEqual(A.normalize_url("https://x.com/example_handle_two"),
                         "twitter.com/example_handle_two")
    def test_youtube(self):
        self.assertEqual(A.normalize_url("https://youtube.com/@handle"), "youtube.com/@handle")
        self.assertEqual(A.normalize_url("https://youtube.com/c/handle"), "youtube.com/c/handle")
    def test_bsky(self):
        self.assertEqual(A.normalize_url("https://bsky.app/profile/foo.bsky.social"),
                         "foo.bsky.social")
    def test_reddit(self):
        self.assertEqual(A.normalize_url("https://reddit.com/user/foo"), "reddit.com/user/foo")
        self.assertEqual(A.normalize_url("https://reddit.com/r/bar"), "reddit.com/r/bar")
    def test_instagram_unsupported(self):
        self.assertIsInstance(A.normalize_url("https://www.instagram.com/example_influencer"),
                              A._Sentinel)
    def test_garbage_unsupported(self):
        self.assertIsInstance(A.normalize_url("not a url"), A._Sentinel)
        self.assertIsInstance(A.normalize_url(""), A._Sentinel)
        self.assertIsInstance(A.normalize_url("   "), A._Sentinel)
    def test_facebook_group_member(self):
        self.assertEqual(A.normalize_url("https://www.facebook.com/groups/123/user/456"),
                         "facebook.com/456")
    def test_sentinel_bool_false(self):
        self.assertFalse(bool(A.UNSUPPORTED))
    def test_domain_is(self):
        self.assertTrue(A.domainIs("a.example.com", "example.com"))
        self.assertFalse(A.domainIs("example.com.evil", "example.com"))
    def test_get_partial_path(self):
        self.assertEqual(A.getPartialPath("/a/b/c", 2), "/a/b")
    def test_capture_regex(self):
        self.assertEqual(A.captureRegex("foo123bar", r"foo(\d+)"), "123")
        self.assertIsNone(A.captureRegex("", r"x"))


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        c = A.Config()
        self.assertEqual(c.submit_url, A.SUBMIT_URL)
        self.assertEqual(c.effective_verbosity(), 0)
    def test_load_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "c.ini"
            p.write_text("[another-note]\ndata_dir = /tmp/x\nverbosity = 2\n")
            c = A.Config.load(p)
            self.assertEqual(c.data_dir, Path("/tmp/x"))
            self.assertEqual(c.verbosity, 2)
    def test_resolve_prefers_cli(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / f"{A.FRIENDLY_NAME}.dat").write_bytes(b"x" * A._SPLIT + b"y" * 100)
            (td / f"{A.AVERSE_NAME}.dat").write_bytes(b"x" * A._SPLIT + b"y" * 100)
            self.assertEqual(A.resolve_data_dir(td, A.Config()), td)


class TestReporting(unittest.TestCase):
    def test_refuses_nonkeyable(self):
        with self.assertRaises(ValueError):
            A.submit([{"identifier": "instagram.com/foo", "label": A.FRIENDLY_NAME}], dry_run=True)
    def test_rejects_bad_label(self):
        with self.assertRaises(ValueError):
            A.submit([{"identifier": "facebook.com/x", "label": "bogus"}], dry_run=True)
    def test_noninteractive_aborts(self):
        mon = mock.patch("builtins.input", side_effect=EOFError())
        with mon:
            with self.assertRaises(SystemExit):
                A.submit([{"identifier": "facebook.com/x", "label": A.FRIENDLY_NAME}], dry_run=True)
    def test_dry_run_emits_wire_tokens(self):
        mon = mock.patch("builtins.input", return_value="yes")
        with mon:
            res = A.submit([{"identifier": "facebook.com/x", "label": A.FRIENDLY_NAME},
                            {"identifier": "facebook.com/y", "label": A.AVERSE_NAME}], dry_run=True)
        self.assertEqual(res["action"], "dry-run")
        labels = {e["label"] for e in res["preview"]["entries"]}
        self.assertEqual(labels, {"t-friendly", "transphobic"})
    def test_each_item_separate(self):
        mon = mock.patch("builtins.input", side_effect=["no", "yes"])
        with mon:
            res = A.submit([{"identifier": "facebook.com/a", "label": A.FRIENDLY_NAME},
                            {"identifier": "facebook.com/b", "label": A.AVERSE_NAME}], dry_run=True)
        self.assertEqual(res["confirmed_count"], 1)
        self.assertEqual(res["preview"]["entries"][0]["identifier"], "facebook.com/b")
    def test_envelope_shape(self):
        env = A.encrypt_submission({"installationId": "x", "lastError": None,
                                    "entries": [{"identifier": "facebook.com/a", "label": "t-friendly"}]})
        for k in ("_comment", "asymmetricallyEncryptedSymmetricKey",
                  "symmetricInitializationVector", "symmetricallyEncryptedData", "version"):
            self.assertIn(k, env)
        self.assertEqual(env["version"], A.PROTOCOL_VERSION)
    def test_installation_id(self):
        self.assertTrue(A.new_installation_id())


class TestCLI(unittest.TestCase):
    def _run(self, argv, chdir=None):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            f, a = A.synthesize(["facebook.com/alice"], ["facebook.com/carol"]).values()
            A.write_filter(f, td / f"{A.FRIENDLY_NAME}.dat")
            A.write_filter(a, td / f"{A.AVERSE_NAME}.dat")
            cwd = chdir or td
            old = os.getcwd()
            os.chdir(cwd)
            try:
                out = io.StringIO()
                with mock.patch("sys.stdout", out):
                    rc = A.main(argv)
                return rc, out.getvalue()
            finally:
                os.chdir(old)

    def test_classify_args(self):
        rc, out = self._run(["classify", "facebook.com/alice", "facebook.com/carol", "facebook.com/z"])
        self.assertEqual(rc, 0)
        self.assertIn(A.FRIENDLY_NAME, out)
        self.assertIn(A.AVERSE_NAME, out)
        self.assertIn("neither", out)
    def test_classify_stdin(self):
        rc, out = self._run(["classify"])
        # no stdin -> no keys -> nothing; ensure clean rc
        self.assertEqual(rc, 0)
    def test_classify_json(self):
        rc, out = self._run(["classify", "--json", "facebook.com/alice"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["labels"]["facebook.com/alice"], A.FRIENDLY_NAME)
    def test_classify_fail_unsupported(self):
        rc, out = self._run(["classify", "--fail-on-unsupported", "https://instagram.com/foo"])
        self.assertEqual(rc, A.EXIT_UNSUPPORTED)
    def test_estimate(self):
        rc, out = self._run(["estimate"])
        self.assertEqual(rc, 0)
        self.assertIn(A.FRIENDLY_NAME, out)
    def test_selfcheck(self):
        rc = A.selfcheck()
        self.assertEqual(rc, 0)
    def test_update_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            res = A.maybe_update(td, force=True, dry_run=True)
            self.assertIn(res["action"], ("would-update", "skipped", "updated"))


class TestSelfcheck(unittest.TestCase):
    def test_selfcheck_zero_mismatch(self):
        self.assertEqual(A.selfcheck(), 0)


class TestEdgeCoverage(unittest.TestCase):
    def test_unwrap_nested_fb(self):
        from urllib.parse import urlsplit
        u = urlsplit("https://www.facebook.com/l.php?u=https%3A%2F%2Ftwitter.com%2Ffoo")
        # _unwrap_nested returns the unquoted nested URL; _impl re-normalizes it
        # through normalize_url('http://' + nested), stripping the scheme.
        self.assertEqual(A._unwrap_nested(u), "https://twitter.com/foo")
    def test_unwrap_nested_none(self):
        from urllib.parse import urlsplit
        self.assertIsNone(A._unwrap_nested(urlsplit("https://facebook.com/normal")))
    def test_get_path_part(self):
        self.assertEqual(A.getPathPart("/a/b/c", 1), "b")
        self.assertIsNone(A.getPathPart("/a", 1))
    def test_save_state(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            A._save_state(td, {"version": "1"})
            self.assertEqual(json.loads((td / A.STATE_FILE).read_text())["version"], "1")
    def test_read_stdin_keys(self):
        fake = io.StringIO("facebook.com/a\nfacebook.com/b\n")
        with mock.patch("sys.stdin", fake):
            self.assertEqual(A.read_stdin_keys(), ["facebook.com/a", "facebook.com/b"])
        # tty -> empty
        class Tty:
            isatty = lambda self: True
        with mock.patch("sys.stdin", Tty()):
            self.assertEqual(A.read_stdin_keys(), [])
    def test_default_data_dir_finds_bundled(self):
        here = Path(__file__).resolve().parent
        self.assertTrue((here / "data" / f"{A.FRIENDLY_NAME}.dat").exists())
        self.assertEqual(A.default_data_dir(), here / "data")
    def test_build_parser_smoke(self):
        p = A.build_parser()
        ns = p.parse_args(["classify", "--json", "x"])
        self.assertEqual(ns.cmd, "classify")
        ns2 = p.parse_args(["report", "--dry-run", "facebook.com/x:transgender_friendly"])
        self.assertEqual(ns2.cmd, "report")
        self.assertTrue(ns2.dry_run)
    def test_prompt_confirm_yes(self):
        with mock.patch("builtins.input", return_value="yes"):
            self.assertTrue(A._prompt_confirm("facebook.com/x", A.FRIENDLY_NAME))
    def test_prompt_confirm_no(self):
        with mock.patch("builtins.input", return_value="no"):
            self.assertFalse(A._prompt_confirm("facebook.com/x", A.FRIENDLY_NAME))
    def test_fill_bits(self):
        f = A.BloomFilter.empty(1000, 20)
        f.add("z")
        self.assertGreater(f.fill_bits(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
