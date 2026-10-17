import contextlib
import io
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from cryptctl import cli, crypto, watcher
from cryptctl.config import Config

PASSWORD = "contraseña-de-prueba"
FAST_KDF = dict(crypto.KDF_DEFAULTS, n=2**10)


def run(*argv, env_password=PASSWORD):
    out, err = io.StringIO(), io.StringIO()
    env = {cli.ENV_PASSWORD: env_password} if env_password else {}
    with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self._kdf = mock.patch.object(crypto, "KDF_DEFAULTS", FAST_KDF)
        self._kdf.start()
        self.cwd = os.getcwd()
        os.chdir(self.root)
        code, _, err = run("init", "--max-size", "1MB")
        self.assertEqual(code, 0, err)
        self.cfg = Config.load(self.root)
        self.vault = self.root / "vault"

    def tearDown(self):
        os.chdir(self.cwd)
        self._kdf.stop()
        self._tmp.cleanup()

    def test_init_layout(self):
        self.assertTrue((self.root / ".cryptctl/config.json").is_file())
        self.assertTrue((self.vault / ".gitkeep").is_file())
        self.assertIn("/vault/**", (self.root / ".gitignore").read_text())
        code, _, err = run("init")
        self.assertEqual(code, 1)
        self.assertIn("--force", err)

    def test_encrypt_decrypt_roundtrip(self):
        data = os.urandom(200_000)
        (self.vault / "sub").mkdir()
        (self.vault / "sub" / "a.bin").write_bytes(data)
        self.assertEqual(run("encrypt")[0], 0)
        self.assertFalse((self.vault / "sub" / "a.bin").exists())
        self.assertTrue((self.vault / "sub" / "a.bin.enc").is_file())

        code, out, _ = run("get", "files", "-o", "wide")
        self.assertIn("sub/a.bin.enc", out)
        self.assertIn("Encrypted", out)

        self.assertEqual(run("decrypt", "--all")[0], 0)
        self.assertEqual((self.root / "decrypted" / "sub" / "a.bin").read_bytes(), data)
        # no sobrescribe sin --force
        self.assertEqual(run("decrypt", "sub/a.bin")[0], 1)
        self.assertEqual(run("decrypt", "sub/a.bin", "--force")[0], 0)

    def test_wrong_password(self):
        (self.vault / "a.txt").write_text("hola")
        code, _, err = run("encrypt", env_password="incorrecta")
        self.assertEqual(code, 1)
        self.assertIn("contraseña incorrecta", err)
        self.assertTrue((self.vault / "a.txt").exists())

    def test_oversize_goes_to_quarantine(self):
        big = self.vault / "big.iso"
        with open(big, "wb") as f:
            f.truncate(2 * 1024**2)
        run("encrypt")
        self.assertFalse(big.exists())
        self.assertTrue((self.root / ".cryptctl/quarantine/big.iso").is_file())
        self.assertIn("Quarantined", run("get", "files")[1])

    def test_name_collision(self):
        (self.vault / "a.txt").write_text("uno")
        run("encrypt")
        (self.vault / "a.txt").write_text("dos")
        run("encrypt")
        self.assertTrue((self.vault / "a (1).txt.enc").is_file())

    def test_passwd(self):
        (self.vault / "a.txt").write_text("hola")
        run("encrypt")
        with mock.patch.dict(os.environ, {cli.ENV_NEW_PASSWORD: "nueva-contraseña-123"}):
            self.assertEqual(run("passwd")[0], 0)
        self.assertEqual(run("decrypt", "a.txt")[0], 1)
        code, _, err = run("decrypt", "a.txt", env_password="nueva-contraseña-123")
        self.assertEqual(code, 0, err)
        self.assertEqual((self.root / "decrypted" / "a.txt").read_text(), "hola")

    def test_config_set(self):
        self.assertEqual(run("config", "set", "max-size", "5MB")[0], 0)
        self.assertEqual(run("config", "get", "max-size")[1].strip(), "5.0MB")
        self.assertEqual(run("config", "set", "output-dir", "vault/out")[0], 1)
        self.assertEqual(run("config", "set", "oversize-action", "nope")[0], 1)
        self.assertNotIn(self.cfg.wrapped_key, run("config", "view")[1])

    def test_git_only_sees_encrypted(self):
        (self.vault / "a.txt").write_text("hola")
        (self.vault / "b.txt").write_text("pendiente")
        watcher.process_file(self.cfg, self.cfg.unlock(PASSWORD), self.vault / "a.txt")
        status = subprocess.run(["git", "status", "--porcelain", "-uall"], capture_output=True,
                                text=True, check=True).stdout
        self.assertIn("vault/a.txt.enc", status)
        self.assertNotIn("b.txt", status)

    def test_watcher_waits_until_file_is_stable(self):
        self.cfg.settle_seconds = 0.5
        w = watcher.Watcher(self.cfg, self.cfg.unlock(PASSWORD), poll=True, interval=0.1)
        t = threading.Thread(target=w.run, daemon=True)
        with contextlib.redirect_stderr(io.StringIO()):
            t.start()
            path = self.vault / "lento.txt"
            with open(path, "wb") as f:  # escritura lenta: no debe cifrarse a medias
                for _ in range(5):
                    f.write(b"x" * 1000)
                    f.flush()
                    time.sleep(0.2)
            deadline = time.time() + 5
            while not (self.vault / "lento.txt.enc").exists() and time.time() < deadline:
                time.sleep(0.1)
            w.stop()
            t.join(5)
        with open(self.vault / "lento.txt.enc", "rb") as f:
            out = io.BytesIO()
            crypto.decrypt_stream(self.cfg.unlock(PASSWORD), f, out)
        self.assertEqual(out.getvalue(), b"x" * 5000)
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
