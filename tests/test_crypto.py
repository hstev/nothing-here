import io
import os
import unittest

from cryptctl import crypto
from cryptctl.config import human_size, parse_size

CHUNK = 1024  # chunks pequeños para ejercitar varios bloques rápido


def enc(dek, data, chunk=CHUNK):
    out = io.BytesIO()
    crypto.encrypt_stream(dek, io.BytesIO(data), out, chunk)
    return out.getvalue()


def dec(dek, blob):
    out = io.BytesIO()
    crypto.decrypt_stream(dek, io.BytesIO(blob), out)
    return out.getvalue()


class StreamTest(unittest.TestCase):
    def setUp(self):
        self.dek = crypto.new_dek()

    def test_roundtrip_sizes(self):
        for size in (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 5 * CHUNK + 17):
            with self.subTest(size=size):
                data = os.urandom(size)
                blob = enc(self.dek, data)
                self.assertEqual(dec(self.dek, blob), data)
                self.assertEqual(crypto.plaintext_size(len(blob), CHUNK), size)

    def test_default_chunk_large(self):
        data = os.urandom(3 * crypto.DEFAULT_CHUNK + 5)
        blob = enc(self.dek, data, crypto.DEFAULT_CHUNK)
        self.assertEqual(dec(self.dek, blob), data)

    def test_wrong_key(self):
        blob = enc(self.dek, b"secreto")
        with self.assertRaises(crypto.CorruptFile):
            dec(crypto.new_dek(), blob)

    def test_tampered_byte(self):
        blob = bytearray(enc(self.dek, os.urandom(3 * CHUNK)))
        blob[crypto.HEADER.size + 5] ^= 1
        with self.assertRaises(crypto.CorruptFile):
            dec(self.dek, bytes(blob))

    def test_tampered_header(self):
        blob = bytearray(enc(self.dek, b"hola"))
        blob[-crypto.HEADER.size] ^= 1  # dentro del salt
        blob[crypto.HEADER.size - 1] ^= 1
        with self.assertRaises(crypto.CorruptFile):
            dec(self.dek, bytes(blob))

    def test_truncated_at_chunk_boundary(self):
        blob = enc(self.dek, os.urandom(3 * CHUNK))
        cut = crypto.HEADER.size + 2 * (CHUNK + crypto.TAG_SIZE)
        with self.assertRaises(crypto.CorruptFile):
            dec(self.dek, blob[:cut])

    def test_reordered_chunks(self):
        blob = enc(self.dek, os.urandom(3 * CHUNK))
        h, b = crypto.HEADER.size, CHUNK + crypto.TAG_SIZE
        c0, c1 = blob[h:h + b], blob[h + b:h + 2 * b]
        with self.assertRaises(crypto.CorruptFile):
            dec(self.dek, blob[:h] + c1 + c0 + blob[h + 2 * b:])

    def test_not_cryptctl(self):
        with self.assertRaises(crypto.CorruptFile):
            dec(self.dek, b"hola mundo, esto no es un archivo cifrado")

    def test_huge_chunk_header_rejected(self):
        blob = bytearray(enc(self.dek, b"x"))
        blob[9:13] = (crypto.MAX_CHUNK + 1).to_bytes(4, "big")
        with self.assertRaises(crypto.CorruptFile):
            dec(self.dek, bytes(blob))


class KeyWrapTest(unittest.TestCase):
    def test_wrap_unwrap(self):
        salt, dek = os.urandom(16), crypto.new_dek()
        kek = crypto.derive_kek("contraseña", salt, 2**10, 8, 1)
        self.assertEqual(crypto.unwrap_key(kek, crypto.wrap_key(kek, dek)), dek)
        bad = crypto.derive_kek("otra", salt, 2**10, 8, 1)
        with self.assertRaises(crypto.InvalidPassword):
            crypto.unwrap_key(bad, crypto.wrap_key(kek, dek))


class SizeTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_size("100MB"), 100 * 1024**2)
        self.assertEqual(parse_size("1.5G"), int(1.5 * 1024**3))
        self.assertEqual(parse_size("512k"), 512 * 1024)
        self.assertEqual(parse_size("2048"), 2048)
        self.assertEqual(parse_size("10 MiB"), 10 * 1024**2)
        for bad in ("", "abc", "-1", "0", "10XB"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_size(bad)

    def test_human(self):
        self.assertEqual(human_size(10), "10B")
        self.assertEqual(human_size(100 * 1024**2), "100.0MB")


if __name__ == "__main__":
    unittest.main()
