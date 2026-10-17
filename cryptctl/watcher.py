"""Vigilancia de la carpeta y cifrado automático de lo que se suba."""

from __future__ import annotations

import os
import queue
import shutil
import stat
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

from . import crypto
from .config import ENC_SUFFIX, PART_SUFFIX, Config, human_size

# Margen mínimo de disco libre además del tamaño del archivo a cifrar.
DISK_MARGIN = 16 * 1024**2
# Espera antes de reintentar un archivo que no se pudo cifrar por falta de espacio.
NOSPACE_BACKOFF = 30.0
# Re-escaneo completo periódico como red de seguridad (eventos perdidos).
RESCAN_EVERY = 30.0

try:  # watchdog es opcional: sin él se usa polling
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    HAS_WATCHDOG = True
except ImportError:  # pragma: no cover - depende del entorno
    FileSystemEventHandler = object
    HAS_WATCHDOG = False


def log(level: str, msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} {level:<5} {msg}", file=sys.stderr, flush=True)


@dataclass
class Result:
    action: str  # encrypted | quarantined | deleted | oversize | changed | nospace | gone
    src: Path
    dst: Path | None = None
    size: int = 0


# --- selección de archivos -----------------------------------------------------

def is_candidate(path: Path, watch: Path) -> bool:
    """Archivo regular en texto plano dentro de la carpeta vigilada."""
    try:
        rel = path.relative_to(watch)
    except ValueError:
        return False
    if any(part.startswith(".") for part in rel.parts):
        return False
    if path.name.endswith((ENC_SUFFIX, PART_SUFFIX)):
        return False
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _walk(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            yield Path(dirpath) / name


def iter_plain(watch: Path) -> Iterator[Path]:
    return (p for p in _walk(watch) if is_candidate(p, watch))


def iter_encrypted(watch: Path) -> Iterator[Path]:
    return (p for p in _walk(watch) if p.name.endswith(ENC_SUFFIX) and not p.name.startswith("."))


def iter_quarantined(cfg: Config) -> Iterator[Path]:
    return _walk(cfg.quarantine_path)


def _split_ext(name: str) -> tuple[str, str]:
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:
        return name, ""
    return stem, "." + ext


def unique_path(path: Path, suffix: str = "") -> Path:
    """Devuelve path+suffix si está libre; si no 'a (1).txt'+suffix, 'a (2).txt'+suffix..."""
    cand = path.with_name(path.name + suffix)
    stem, ext = _split_ext(path.name)
    i = 1
    while cand.exists():
        cand = path.with_name(f"{stem} ({i}){ext}{suffix}")
        i += 1
    return cand


def part_path(path: Path) -> Path:
    """Temporal oculto junto al destino (lo ignoran watcher y git)."""
    return path.with_name(f".{path.name}{PART_SUFFIX}")


# --- procesamiento de un archivo -----------------------------------------------

def _handle_oversize(cfg: Config, path: Path, size: int) -> Result:
    if cfg.oversize_action == "delete":
        path.unlink()
        return Result("deleted", path, size=size)
    if cfg.oversize_action == "quarantine":
        try:
            rel = path.relative_to(cfg.watch_path)
        except ValueError:
            rel = Path(path.name)
        dst = unique_path(cfg.quarantine_path / rel)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(dst))
        return Result("quarantined", path, dst, size)
    return Result("oversize", path, size=size)


def process_file(cfg: Config, dek: bytes, path: Path) -> Result:
    """Cifra un archivo (o lo manda a cuarentena si es demasiado grande)."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return Result("gone", path)
    if not stat.S_ISREG(st.st_mode):
        return Result("gone", path)
    if st.st_size > cfg.max_file_size:
        return _handle_oversize(cfg, path, st.st_size)
    if shutil.disk_usage(path.parent).free < st.st_size + DISK_MARGIN:
        return Result("nospace", path, size=st.st_size)

    dst = unique_path(path, ENC_SUFFIX)
    tmp = part_path(dst)
    try:
        with open(path, "rb") as src, open(tmp, "wb") as out:
            crypto.encrypt_stream(dek, src, out)
            out.flush()
            os.fsync(out.fileno())
            after = os.fstat(src.fileno())
        now = path.lstat()
        sig = lambda s: (s.st_ino, s.st_size, s.st_mtime_ns)  # noqa: E731
        if not (sig(st) == sig(after) == sig(now)):
            tmp.unlink()
            return Result("changed", path, size=st.st_size)
        os.replace(tmp, dst)
        path.unlink()
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return Result("encrypted", path, dst, st.st_size)


def describe_result(cfg: Config, r: Result) -> tuple[str, str]:
    rel = lambda p: os.path.relpath(p, cfg.root)  # noqa: E731
    limit = human_size(cfg.max_file_size)
    match r.action:
        case "encrypted":
            return "INFO", f"cifrado {rel(r.src)} -> {rel(r.dst)} ({human_size(r.size)})"
        case "quarantined":
            return "WARN", f"{rel(r.src)} ({human_size(r.size)}) supera {limit}: movido a {rel(r.dst)} SIN cifrar"
        case "deleted":
            return "WARN", f"{rel(r.src)} ({human_size(r.size)}) supera {limit}: eliminado"
        case "oversize":
            return "WARN", f"{rel(r.src)} ({human_size(r.size)}) supera {limit}: ignorado, queda SIN cifrar"
        case "nospace":
            return "WARN", f"sin espacio en disco para cifrar {rel(r.src)} ({human_size(r.size)}); se reintentará"
        case "changed":
            return "INFO", f"{rel(r.src)} cambió mientras se cifraba; se reintentará"
        case _:
            return "DEBUG", f"{rel(r.src)} ya no existe"


# --- watcher -------------------------------------------------------------------

class _Handler(FileSystemEventHandler):
    def __init__(self, events: queue.SimpleQueue):
        self.events = events

    def on_any_event(self, event):  # noqa: D401 - API de watchdog
        if event.event_type not in ("created", "modified", "moved", "closed"):
            return
        path = getattr(event, "dest_path", "") or event.src_path
        self.events.put((Path(os.fsdecode(path)), event.is_directory))


class Watcher:
    def __init__(self, cfg: Config, dek: bytes, poll: bool = False, interval: float = 1.0):
        self.cfg = cfg
        self.dek = dek
        self.poll = poll or not HAS_WATCHDOG
        self.interval = interval
        self.events: queue.SimpleQueue = queue.SimpleQueue()
        # path -> (size, mtime_ns, desde_cuando_estable)
        self.pending: dict[Path, tuple[int, int, float]] = {}
        # archivos que no se reintentan mientras no cambien (oversize con 'skip', errores)
        self.ignored: dict[Path, tuple[int, int]] = {}
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def touch(self, path: Path) -> None:
        self.pending.setdefault(path, (-1, -1, time.monotonic()))

    def scan(self) -> None:
        for p in iter_plain(self.cfg.watch_path):
            self.touch(p)

    def _drain_events(self) -> None:
        rescan = False
        while True:
            try:
                path, is_dir = self.events.get_nowait()
            except queue.Empty:
                break
            if is_dir:
                rescan = True
            elif is_candidate(path, self.cfg.watch_path):
                self.touch(path)
        if rescan:
            self.scan()

    def check_pending(self) -> None:
        now = time.monotonic()
        for path, (size, mtime, since) in list(self.pending.items()):
            try:
                st = path.lstat()
            except FileNotFoundError:
                del self.pending[path]
                continue
            sig = (st.st_size, st.st_mtime_ns)
            if self.ignored.get(path) == sig:
                del self.pending[path]
                continue
            if sig != (size, mtime):  # sigue escribiéndose: reiniciar espera
                self.pending[path] = (*sig, now)
                continue
            if now - since < self.cfg.settle_seconds:
                continue
            del self.pending[path]
            self._handle(path, sig)

    def _handle(self, path: Path, sig: tuple[int, int]) -> None:
        self.ignored.pop(path, None)
        try:
            r = process_file(self.cfg, self.dek, path)
        except Exception as e:  # noqa: BLE001 - el watcher no debe caerse
            log("ERROR", f"no se pudo procesar {os.path.relpath(path, self.cfg.root)}: {e}")
            self.ignored[path] = sig
            return
        if r.action == "gone":
            return
        level, msg = describe_result(self.cfg, r)
        log(level, msg)
        if r.action == "changed":
            self.touch(path)
        elif r.action == "nospace":
            self.pending[path] = (*sig, time.monotonic() + NOSPACE_BACKOFF)
        elif r.action == "oversize":
            self.ignored[path] = sig

    def run(self) -> None:
        self.cfg.watch_path.mkdir(parents=True, exist_ok=True)
        observer = None
        if not self.poll:
            observer = Observer()
            observer.schedule(_Handler(self.events), str(self.cfg.watch_path), recursive=True)
            observer.start()
        mode = "polling" if observer is None else "eventos (watchdog)"
        log("INFO", f"vigilando {os.path.relpath(self.cfg.watch_path, self.cfg.root)}/ en modo {mode}; "
                    f"máx {human_size(self.cfg.max_file_size)}, sobretamaño -> {self.cfg.oversize_action}")
        try:
            self.scan()
            last_scan = time.monotonic()
            while not self._stop.is_set():
                self._drain_events()
                now = time.monotonic()
                every = self.interval if observer is None else RESCAN_EVERY
                if now - last_scan >= every:
                    self.scan()
                    last_scan = now
                self.check_pending()
                self._stop.wait(0.25)
        finally:
            if observer is not None:
                observer.stop()
                observer.join()
            log("INFO", "watcher detenido")
