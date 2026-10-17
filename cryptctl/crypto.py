"""Primitivas criptográficas de cryptctl.

Modelo de claves:
    contraseña --scrypt--> KEK --AES-GCM--> DEK envuelta (guardada en config)
    DEK + salt por archivo --HKDF--> clave del archivo

Formato de archivo .enc (STREAM, memoria constante):
    header = MAGIC(8) | version(1) | chunk_size(4) | salt(16)
    chunks = AES-256-GCM(clave_archivo, nonce=contador(11)|ultimo(1), aad=header)
"""

from __future__ import annotations

import os
import struct
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CRYPTCTL"
FORMAT_VERSION = 1
DEFAULT_CHUNK = 64 * 1024
MAX_CHUNK = 16 * 1024 * 1024
TAG_SIZE = 16
HEADER = struct.Struct(">8sBI16s")

KDF_DEFAULTS = {"name": "scrypt", "n": 2**17, "r": 8, "p": 1}
_WRAP_AAD = b"cryptctl/dek/v1"
_FILE_INFO = b"cryptctl/file/v1"


class CryptoError(Exception):
    """Error genérico de cifrado/descifrado."""


class InvalidPassword(CryptoError):
    pass


class CorruptFile(CryptoError):
    pass


# --- claves -----------------------------------------------------------------

def new_dek() -> bytes:
    return os.urandom(32)


def derive_kek(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))


def wrap_key(kek: bytes, dek: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(kek).encrypt(nonce, dek, _WRAP_AAD)


def unwrap_key(kek: bytes, blob: bytes) -> bytes:
    try:
        return AESGCM(kek).decrypt(blob[:12], blob[12:], _WRAP_AAD)
    except InvalidTag:
        raise InvalidPassword("contraseña incorrecta") from None


def _file_key(dek: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=_FILE_INFO).derive(dek)


def _nonce(counter: int, last: bool) -> bytes:
    if counter >= 1 << 88:
        raise CryptoError("archivo demasiado grande para el formato")
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def _read_full(src: BinaryIO, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        part = src.read(size - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


# --- streaming ----------------------------------------------------------------

def encrypt_stream(dek: bytes, src: BinaryIO, dst: BinaryIO, chunk_size: int = DEFAULT_CHUNK) -> None:
    salt = os.urandom(16)
    header = HEADER.pack(MAGIC, FORMAT_VERSION, chunk_size, salt)
    aes = AESGCM(_file_key(dek, salt))
    dst.write(header)
    counter = 0
    chunk = _read_full(src, chunk_size)
    while True:
        nxt = _read_full(src, chunk_size)
        last = not nxt
        dst.write(aes.encrypt(_nonce(counter, last), chunk, header))
        if last:
            return
        chunk = nxt
        counter += 1


def read_header(src: BinaryIO) -> tuple[bytes, int, int, bytes]:
    """Devuelve (header_crudo, version, chunk_size, salt) validando el header."""
    raw = _read_full(src, HEADER.size)
    if len(raw) != HEADER.size:
        raise CorruptFile("no es un archivo cryptctl (header incompleto)")
    magic, version, chunk_size, salt = HEADER.unpack(raw)
    if magic != MAGIC:
        raise CorruptFile("no es un archivo cryptctl")
    if version != FORMAT_VERSION:
        raise CorruptFile(f"versión de formato no soportada: {version}")
    if not 0 < chunk_size <= MAX_CHUNK:
        raise CorruptFile(f"chunk_size inválido: {chunk_size}")
    return raw, version, chunk_size, salt


def decrypt_stream(dek: bytes, src: BinaryIO, dst: BinaryIO) -> None:
    header, _, chunk_size, salt = read_header(src)
    aes = AESGCM(_file_key(dek, salt))
    block_size = chunk_size + TAG_SIZE
    counter = 0
    block = _read_full(src, block_size)
    while True:
        nxt = _read_full(src, block_size)
        last = not nxt
        if len(block) < TAG_SIZE:
            raise CorruptFile("archivo truncado")
        try:
            dst.write(aes.decrypt(_nonce(counter, last), block, header))
        except InvalidTag:
            raise CorruptFile("archivo corrupto, manipulado o cifrado con otra clave") from None
        if last:
            return
        block = nxt
        counter += 1


def plaintext_size(total_size: int, chunk_size: int) -> int:
    """Tamaño original calculado a partir del tamaño del .enc."""
    body = total_size - HEADER.size
    block = chunk_size + TAG_SIZE
    chunks = max(1, -(-body // block))
    return body - chunks * TAG_SIZE
