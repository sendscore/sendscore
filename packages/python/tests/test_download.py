import functools
import http.server
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from sendscore import SendScoreError
from sendscore._binary import download, matches_pin, pin_for

FIXTURES = Path(__file__).resolve().parents[3] / "conformance" / "release"
PINS = {k: (v["archive"], v["binary"]) for k, v in json.loads((FIXTURES / "pins.json").read_text()).items()}


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class Download(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = functools.partial(Quiet, directory=str(FIXTURES))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_installs_the_binary_and_nothing_else(self):
        for target in (("linux", "amd64"), ("darwin", "arm64"), ("windows", "amd64")):
            with self.subTest(target), tempfile.TemporaryDirectory() as tmp:
                cache = Path(tmp) / "cache"
                path = download("0.0.0-test", f"{self.base}/good", cache, PINS["_".join(target)], target)
                self.assertIn(b"fake sendscore", path.read_bytes())
                if os.name != "nt":
                    self.assertTrue(os.access(path, os.X_OK))
                self.assertEqual([p.name for p in cache.iterdir()], [path.name])
                self.assertFalse((Path(tmp) / "evil").exists())

    def test_refuses_a_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            with self.assertRaises(SendScoreError):
                download("0.0.0-test", f"{self.base}/altered", cache, PINS["linux_amd64"], ("linux", "amd64"))
            self.assertFalse(cache.exists())

    def test_fails_on_a_missing_release(self):
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(SendScoreError):
            download("0.0.0-test", f"{self.base}/nothing", Path(tmp) / "cache", PINS["linux_amd64"], ("linux", "amd64"))

    def test_refuses_a_binary_that_does_not_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "cache"
            wrong = (PINS["linux_amd64"][0], "0" * 64)
            with self.assertRaises(SendScoreError):
                download("0.0.0-test", f"{self.base}/good", cache, wrong, ("linux", "amd64"))
            self.assertFalse(cache.exists())

    def test_cached_binary_is_trusted_only_while_it_matches(self):
        pin = PINS["linux_amd64"]
        with tempfile.TemporaryDirectory() as tmp:
            path = download("0.0.0-test", f"{self.base}/good", Path(tmp) / "cache", pin, ("linux", "amd64"))
            self.assertTrue(matches_pin(path, pin))
            path.write_text("planted")
            self.assertFalse(matches_pin(path, pin))

    def test_no_pin_means_no_download(self):
        with self.assertRaises(SendScoreError):
            pin_for("linux", "amd64", {})


if __name__ == "__main__":
    unittest.main()
