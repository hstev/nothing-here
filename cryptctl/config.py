"""Configuración del proyecto (.cryptctl/config.json) y utilidades."""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import crypto

CONFIG_DIR = ".cryptctl"
CONFIG_FILE = "config.json"
QUARANTINE_DIR = "quarantine"
ENC_SUFFIX = ".enc"
PART_SUFFIX = ".part"
OVERSIZE_ACTIONS = ("quarantine", "skip", "delete")

GITIGNORE_BEGIN = "# >>> cryptctl (bloque gestionado, no editar)"
GITIGNORE_END = "# <<< cryptctl"


class ConfigError(Exception):
    pass


@dataclass
class Config:
    root: Path
    watch_dir: str = "vault"
    output_dir: str = "decrypted"
    max_file_size: int = 100 * 1024**2
    oversize_action: str = "quarantine"
    settle_seconds: float = 2.0
    kdf: dict = field(default_factory=dict)
    wrapped_key: str = ""
    version: int = 1

    # --- rutas ---
    @property
    def config_path(self) -> Path:
        return self.root / CONFIG_DIR / CONFIG_FILE

    @property
    def watch_path(self) -> Path:
        return self.root / self.watch_dir

    @property
    def output_path(self) -> Path:
        return self.root / self.output_dir

    @property
    def quarantine_path(self) -> Path:
        return self.root / CONFIG_DIR / QUARANTINE_DIR

    # --- persistencia ---
    def save(self) -> None:
        data = asdict(self)
        data.pop("root")
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.config_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n")
        os.replace(tmp, self.config_path)

    @classmethod
    def load(cls, root: Path) -> "Config":
        path = root / CONFIG_DIR / CONFIG_FILE
        try:
            data = json.loads(path.read_text())
        except FileNotFoundError:
            raise ConfigError(f"no existe {path}; ejecuta 'cryptctl init'") from None
        except json.JSONDecodeError as e:
            raise ConfigError(f"config inválida en {path}: {e}") from None
        known = {f for f in cls.__dataclass_fields__ if f != "root"}
        return cls(root=root, **{k: v for k, v in data.items() if k in known})

    # --- claves ---
    def set_password(self, password: str, dek: bytes) -> None:
        salt = os.urandom(16)
        kdf = dict(crypto.KDF_DEFAULTS, salt=_b64(salt))
        kek = crypto.derive_kek(password, salt, kdf["n"], kdf["r"], kdf["p"])
        self.kdf = kdf
        self.wrapped_key = _b64(crypto.wrap_key(kek, dek))

    def unlock(self, password: str) -> bytes:
        if self.kdf.get("name") != "scrypt":
            raise ConfigError(f"KDF no soportado: {self.kdf.get('name')}")
        kek = crypto.derive_kek(
            password, _unb64(self.kdf["salt"]), self.kdf["n"], self.kdf["r"], self.kdf["p"]
        )
        return crypto.unwrap_key(kek, _unb64(self.wrapped_key))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def find_root(start: Path | None = None) -> Path:
    """Busca hacia arriba un directorio con .cryptctl/config.json (como git)."""
    cur = (start or Path.cwd()).resolve()
    for d in (cur, *cur.parents):
        if (d / CONFIG_DIR / CONFIG_FILE).is_file():
            return d
    raise ConfigError("no se encontró un proyecto cryptctl; ejecuta 'cryptctl init' o usa --root")


def default_init_root(start: Path | None = None) -> Path:
    """Raíz del repo git si existe; si no, el directorio actual."""
    cur = (start or Path.cwd()).resolve()
    for d in (cur, *cur.parents):
        if (d / ".git").exists():
            return d
    return cur


# --- tamaños ----------------------------------------------------------------

_UNITS = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(text: str) -> int:
    """'100MB', '1.5G', '512k', '2048' -> bytes (unidades binarias)."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?)(?:i?b)?\s*", text.lower())
    if not m:
        raise ValueError(f"tamaño inválido: {text!r} (ej: 100MB, 1.5G, 512k)")
    value = int(float(m.group(1)) * _UNITS[m.group(2)])
    if value <= 0:
        raise ValueError("el tamaño debe ser mayor que 0")
    return value


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}B"


# --- .gitignore ---------------------------------------------------------------

def gitignore_block(cfg: Config) -> str:
    w = cfg.watch_dir.strip("/")
    o = cfg.output_dir.strip("/")
    return "\n".join([
        GITIGNORE_BEGIN,
        f"/{w}/**",
        f"!/{w}/**/",
        f"!/{w}/**/*{ENC_SUFFIX}",
        f"!/{w}/.gitkeep",
        f"/{o}/",
        f"/{CONFIG_DIR}/{QUARANTINE_DIR}/",
        f"/{CONFIG_DIR}/*.tmp",
        GITIGNORE_END,
    ]) + "\n"


def write_gitignore(cfg: Config) -> Path:
    path = cfg.root / ".gitignore"
    text = path.read_text() if path.exists() else ""
    block = gitignore_block(cfg)
    pattern = re.compile(re.escape(GITIGNORE_BEGIN) + r".*?" + re.escape(GITIGNORE_END) + r"\n?", re.S)
    if pattern.search(text):
        text = pattern.sub(lambda _: block, text)
    else:
        if text and not text.endswith("\n"):
            text += "\n"
        text += ("\n" if text else "") + block
    path.write_text(text)
    return path


def validate_dirs(watch_dir: str, output_dir: str) -> None:
    """Las carpetas deben ser relativas a la raíz y no solaparse entre sí."""
    paths = {}
    for name, value in (("watch-dir", watch_dir), ("output-dir", output_dir)):
        p = Path(value)
        if p.is_absolute() or ".." in p.parts or str(p) in ("", "."):
            raise ConfigError(f"{name} debe ser una subcarpeta relativa a la raíz del proyecto: {value!r}")
        if p.parts[0] in (CONFIG_DIR, ".git"):
            raise ConfigError(f"{name} no puede estar dentro de {p.parts[0]}/")
        paths[name] = p
    w, o = paths["watch-dir"], paths["output-dir"]
    if w == o or w in o.parents or o in w.parents:
        raise ConfigError("watch-dir y output-dir no pueden solaparse (se re-cifraría lo descifrado)")
