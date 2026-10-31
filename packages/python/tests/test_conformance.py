import json
import unittest
from pathlib import Path

from sendscore import SendScoreError, check, diff

ROOT = Path(__file__).resolve().parents[3] / "conformance"
CASES = json.loads((ROOT / "cases.json").read_text())["cases"]


def run(c):
    if c["command"] == "diff":
        return diff(ROOT / c["before"], ROOT / c["after"])
    given = c.get("options", {})
    opts = {k: given[k] for k in ("links", "ip", "mail_from", "helo", "tls") if k in given}
    if "previous" in given:
        opts["previous"] = ROOT / given["previous"]
    path = ROOT / c["message"]
    return check(path.read_bytes() if c["via"] == "stdin" else path, offline=True, **opts)


class Conformance(unittest.TestCase):
    def test_cases(self):
        for c in CASES:
            with self.subTest(c["name"]):
                if c["exit"] > 2:
                    with self.assertRaises(SendScoreError) as e:
                        run(c)
                    self.assertEqual(e.exception.exit_code, c["exit"])
                    continue
                got = run(c)
                changes = got.get("changes") or []
                self.assertEqual([x["field"] for x in changes], c.get("changes", []))
                self.assertEqual([x["worsened"] for x in changes if x.get("worsened")], c.get("worsened", []))
                if c["command"] == "diff":
                    continue
                self.assertEqual(got["verdict"], c["verdict"])
                self.assertEqual(got["ready_to_send"], c["ready_to_send"])
                self.assertEqual({x["id"]: x["status"] for x in got["checks"]}, c["checks"])


if __name__ == "__main__":
    unittest.main()
