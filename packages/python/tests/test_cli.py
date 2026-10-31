import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sendscore
from sendscore import ENGINE_VERSION, KILLED, SendScoreError, check, diff
from sendscore._binary import find_binary

REPO = Path(__file__).resolve().parents[3]
SAMPLE = REPO / "conformance" / "messages" / "clean.eml"
EXE = "sendscore.exe" if sys.platform == "win32" else "sendscore"
REAL = os.environ.get("SENDSCORE_BIN") or str(REPO / "bin" / EXE)


class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls.dir.name)
        cls.built = cls.tmp / "built" / EXE
        subprocess.run(["go", "build", "-o", str(cls.built), "./conformance/fakecli"], cwd=REPO, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def fake(self, mode):
        d = self.tmp / mode
        d.mkdir(exist_ok=True)
        shutil.copy2(self.built, d / EXE)
        return str(d / EXE)

    def using(self, mode):
        return mock.patch.dict(os.environ, {"SENDSCORE_BIN": self.fake(mode)})

    def only_path(self, path):
        env = {k: v for k, v in os.environ.items() if k != "SENDSCORE_BIN"}
        env.update(PATH=path, HOME=str(self.tmp / "home"), XDG_CACHE_HOME=str(self.tmp / "cache"))
        return mock.patch.dict(os.environ, env, clear=True)

    def test_timeout_kills_the_cli(self):
        with self.using("hang"):
            for call in (lambda: check(SAMPLE, timeout=0.2), lambda: diff(SAMPLE, SAMPLE, timeout=0.2)):
                with self.assertRaises(SendScoreError) as e:
                    call()
                self.assertEqual(e.exception.exit_code, KILLED)

    @unittest.skipIf(sys.platform == "win32", "no signals")
    def test_killed_cli_has_one_exit_code(self):
        with self.using("killed"), self.assertRaises(SendScoreError) as e:
            check(SAMPLE)
        self.assertEqual(e.exception.exit_code, KILLED)

    def test_output_that_is_not_a_verdict_is_refused(self):
        with self.using("planted"):
            with self.assertRaises(SendScoreError):
                check(SAMPLE)
            with self.assertRaises(SendScoreError):
                diff(SAMPLE, SAMPLE)

    def test_unknown_fields_and_stderr_are_tolerated(self):
        with self.using("noisy"):
            got = check(SAMPLE)
        self.assertEqual(got["verdict"], "pass")
        self.assertEqual(got["checks"][0]["status"], "brand_new")

    def test_wrong_version_on_path_is_not_run(self):
        self.fake("version-9.9.9")
        with self.only_path(str(self.tmp / "version-9.9.9")), self.assertRaisesRegex(SendScoreError, "no pinned hash"):
            find_binary()

    def test_pinned_version_on_path_is_used(self):
        path = self.fake(f"version-{ENGINE_VERSION}")
        with self.only_path(str(self.tmp / f"version-{ENGINE_VERSION}")):
            self.assertEqual(find_binary(), path)

    def test_relative_path_entries_are_skipped(self):
        name = f"version-{ENGINE_VERSION}"
        os.makedirs(name, exist_ok=True)
        try:
            shutil.copy2(self.fake(name), os.path.join(name, EXE))
            with self.only_path(os.pathsep.join(["", name])), self.assertRaisesRegex(SendScoreError, "no pinned hash"):
                find_binary()
        finally:
            shutil.rmtree(name)

    def test_directory_on_path_does_not_stop_the_search(self):
        path = self.fake(f"version-{ENGINE_VERSION}")
        (self.tmp / "dir" / EXE).mkdir(parents=True, exist_ok=True)
        joined = os.pathsep.join([str(self.tmp / "dir"), str(self.tmp / f"version-{ENGINE_VERSION}")])
        with self.only_path(joined):
            self.assertEqual(find_binary(), path)

    def test_paths_that_look_like_flags_are_files(self):
        with mock.patch.dict(os.environ, {"SENDSCORE_BIN": REAL}):
            for name in ("-", "-dash.eml"):
                shutil.copy(SAMPLE, name)
                try:
                    self.assertTrue(check(name, offline=True)["message"]["subject"])
                finally:
                    os.unlink(name)


if __name__ == "__main__":
    unittest.main()
