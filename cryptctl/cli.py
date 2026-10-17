"""CLI de cryptctl, con verbos al estilo kubectl."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import signal
import sys
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from . import __version__, crypto
from .config import (
    ENC_SUFFIX,
    OVERSIZE_ACTIONS,
    Config,
    ConfigError,
    default_init_root,
    find_root,
    human_size,
    parse_size,
    validate_dirs,
    write_gitignore,
)
from . import watcher

MIN_PASSWORD = 8
ENV_PASSWORD = "CRYPTCTL_PASSWORD"
ENV_NEW_PASSWORD = "CRYPTCTL_NEW_PASSWORD"


class CliError(Exception):
    pass


# --- helpers -------------------------------------------------------------------

def _load(args) -> Config:
    root = Path(args.root).resolve() if args.root else find_root()
    return Config.load(root)


def _ask_password(prompt: str, confirm: bool) -> str:
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repite la contraseña: ") != pw:
        raise CliError("las contraseñas no coinciden")
    return pw


def _password(args, confirm: bool = False) -> str:
    if args.password_file:
        return Path(args.password_file).read_text().rstrip("\r\n")
    if os.environ.get(ENV_PASSWORD):
        return os.environ[ENV_PASSWORD]
    return _ask_password("Contraseña: ", confirm)


def _check_strength(pw: str) -> None:
    if len(pw) < MIN_PASSWORD:
        raise CliError(f"la contraseña debe tener al menos {MIN_PASSWORD} caracteres")
    if len(pw) < 12:
        print("aviso: se recomiendan 12+ caracteres", file=sys.stderr)


def _unlock(cfg: Config, args) -> bytes:
    try:
        return cfg.unlock(_password(args))
    except crypto.InvalidPassword:
        raise CliError("contraseña incorrecta") from None


def _rel(cfg: Config, p: Path) -> str:
    return os.path.relpath(p, cfg.root)


def _age(mtime: float) -> str:
    s = max(0, int(time.time() - mtime))
    for unit, secs in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= secs:
            return f"{s // secs}{unit}"
    return f"{s}s"


def _table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [max(len(str(c)) for c in col) for col in zip(headers, *rows)]
    for row in [headers, *rows]:
        print("   ".join(str(c).ljust(w) for c, w in zip(row, widths)).rstrip())


def _resolve_enc(cfg: Config, name: str) -> Path:
    """Acepta ruta real, ruta relativa a la carpeta vigilada, o el nombre sin '.enc'."""
    candidates = [Path(name), cfg.watch_path / name]
    if not name.endswith(ENC_SUFFIX):
        candidates += [Path(name + ENC_SUFFIX), cfg.watch_path / (name + ENC_SUFFIX)]
    for c in candidates:
        if c.is_file():
            return c.resolve()
    raise CliError(f"no se encontró el archivo cifrado: {name}")


def _inside(child: Path, parent: Path) -> bool:
    child, parent = child.resolve(), parent.resolve()
    return child == parent or parent in child.parents


# --- comandos ------------------------------------------------------------------

def cmd_init(args) -> int:
    root = Path(args.root).resolve() if args.root else default_init_root()
    cfg = Config(root=root, watch_dir=args.dir.strip("/"), max_file_size=parse_size(args.max_size))
    validate_dirs(cfg.watch_dir, cfg.output_dir)
    if cfg.config_path.exists() and not args.force:
        raise CliError(f"ya existe {_rel(cfg, cfg.config_path)}; usa --force para reinicializar "
                       "(¡los archivos cifrados con la clave anterior no se podrán descifrar!)")
    pw = _password(args, confirm=True)
    _check_strength(pw)
    cfg.set_password(pw, crypto.new_dek())
    cfg.save()
    cfg.watch_path.mkdir(parents=True, exist_ok=True)
    (cfg.watch_path / ".gitkeep").touch()
    gi = write_gitignore(cfg)
    print(f"proyecto inicializado en {root}")
    print(f"  carpeta vigilada: {cfg.watch_dir}/   (máx {human_size(cfg.max_file_size)} por archivo)")
    print(f"  config:           {_rel(cfg, cfg.config_path)}   (commitéala: guarda la clave envuelta)")
    print(f"  gitignore:        {_rel(cfg, gi)}   (el texto plano nunca se commitea)")
    print("\nsiguiente paso:  cryptctl watch")
    print("¡No pierdas la contraseña! Sin ella no hay forma de recuperar los archivos.")
    return 0


def cmd_watch(args) -> int:
    cfg = _load(args)
    dek = _unlock(cfg, args)
    w = watcher.Watcher(cfg, dek, poll=args.poll, interval=args.interval)
    signal.signal(signal.SIGTERM, lambda *_: w.stop())
    try:
        w.run()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_encrypt(args) -> int:
    cfg = _load(args)
    if args.paths:
        paths = []
        for p in args.paths:
            path = Path(p).resolve()
            if not watcher.is_candidate(path, cfg.watch_path.resolve()):
                raise CliError(f"{p} no es un archivo en texto plano dentro de {cfg.watch_dir}/")
            paths.append(path)
    else:
        paths = list(watcher.iter_plain(cfg.watch_path))
    if not paths:
        print("nada que cifrar")
        return 0
    dek = _unlock(cfg, args)
    failed = 0
    for path in paths:
        r = watcher.process_file(cfg, dek, path)
        level, msg = watcher.describe_result(cfg, r)
        print(f"{level:<5} {msg}", file=sys.stderr if level != "INFO" else sys.stdout)
        failed += r.action in ("nospace", "changed", "oversize")
    return 1 if failed else 0


def cmd_decrypt(args) -> int:
    cfg = _load(args)
    if args.all:
        files = list(watcher.iter_encrypted(cfg.watch_path))
    elif args.paths:
        files = [_resolve_enc(cfg, p) for p in args.paths]
    else:
        raise CliError("indica archivos a descifrar o usa --all")
    if not files:
        print("no hay archivos cifrados")
        return 0
    to_stdout = args.output == "-"
    if to_stdout and len(files) != 1:
        raise CliError("-o - (stdout) solo admite un archivo")
    out_dir = Path(args.output).resolve() if args.output and not to_stdout else cfg.output_path
    if not to_stdout and _inside(out_dir, cfg.watch_path):
        raise CliError(f"la salida no puede estar dentro de {cfg.watch_dir}/ (se volvería a cifrar)")

    dek = _unlock(cfg, args)
    if to_stdout:
        with open(files[0], "rb") as src:
            crypto.decrypt_stream(dek, src, sys.stdout.buffer)
        return 0

    failed = 0
    watch = cfg.watch_path.resolve()
    for enc in files:
        enc = enc.resolve()
        rel = enc.relative_to(watch) if _inside(enc, watch) else Path(enc.name)
        name = rel.name[: -len(ENC_SUFFIX)] if rel.name.endswith(ENC_SUFFIX) else rel.name + ".dec"
        dest = out_dir / rel.parent / name
        if dest.exists() and not args.force:
            print(f"SKIP  {dest} ya existe (usa --force para sobrescribir)", file=sys.stderr)
            failed += 1
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = watcher.part_path(dest)
        try:
            with open(enc, "rb") as src, open(tmp, "wb") as out:
                crypto.decrypt_stream(dek, src, out)
            os.replace(tmp, dest)
        except crypto.CryptoError as e:
            tmp.unlink(missing_ok=True)
            print(f"ERROR {_rel(cfg, enc)}: {e}", file=sys.stderr)
            failed += 1
            continue
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        print(f"descifrado {_rel(cfg, enc)} -> {os.path.relpath(dest)}")
    return 1 if failed else 0


def _file_rows(cfg: Config) -> list[dict]:
    rows = []
    for p in watcher.iter_encrypted(cfg.watch_path):
        st = p.stat()
        try:
            with open(p, "rb") as f:
                _, _, chunk, _ = crypto.read_header(f)
            orig, status = crypto.plaintext_size(st.st_size, chunk), "Encrypted"
        except crypto.CryptoError:
            orig, status = None, "Invalid"
        rows.append(dict(name=str(p.relative_to(cfg.watch_path)), status=status, size=st.st_size,
                         original_size=orig, mtime=st.st_mtime, path=_rel(cfg, p)))
    for p in watcher.iter_plain(cfg.watch_path):
        st = p.stat()
        status = "Oversize" if st.st_size > cfg.max_file_size else "Pending"
        rows.append(dict(name=str(p.relative_to(cfg.watch_path)), status=status, size=st.st_size,
                         original_size=st.st_size, mtime=st.st_mtime, path=_rel(cfg, p)))
    for p in watcher.iter_quarantined(cfg):
        st = p.stat()
        rows.append(dict(name="quarantine/" + str(p.relative_to(cfg.quarantine_path)), status="Quarantined",
                         size=st.st_size, original_size=st.st_size, mtime=st.st_mtime, path=_rel(cfg, p)))
    return rows


def cmd_get(args) -> int:
    cfg = _load(args)
    rows = _file_rows(cfg)
    if args.output == "json":
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print(f"No hay archivos en {cfg.watch_dir}/.", file=sys.stderr)
        return 0
    headers = ["NAME", "STATUS", "SIZE", "AGE"]
    if args.output == "wide":
        headers += ["ORIGINAL", "PATH"]
    table = []
    for r in rows:
        row = [r["name"], r["status"], human_size(r["size"]), _age(r["mtime"])]
        if args.output == "wide":
            orig = r["original_size"]
            row += ["-" if orig is None else human_size(orig), r["path"]]
        table.append(row)
    _table(headers, table)
    return 0


def cmd_describe(args) -> int:
    cfg = _load(args)
    path = _resolve_enc(cfg, args.path)
    st = path.stat()
    with open(path, "rb") as f:
        _, version, chunk, salt = crypto.read_header(f)
    fields = [
        ("Name", path.name),
        ("Path", _rel(cfg, path)),
        ("Format", f"cryptctl v{version} (AES-256-GCM STREAM, HKDF-SHA256)"),
        ("Chunk size", human_size(chunk)),
        ("Size", f"{human_size(st.st_size)} ({st.st_size} bytes)"),
        ("Original size", f"{human_size(crypto.plaintext_size(st.st_size, chunk))} "
                          f"({crypto.plaintext_size(st.st_size, chunk)} bytes)"),
        ("Modified", datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")),
        ("File salt", salt.hex()),
    ]
    if args.verify:
        dek = _unlock(cfg, args)
        with open(path, "rb") as f, open(os.devnull, "wb") as sink:
            try:
                crypto.decrypt_stream(dek, f, sink)
                fields.append(("Integrity", "OK"))
            except crypto.CryptoError as e:
                fields.append(("Integrity", f"FAILED: {e}"))
    else:
        fields.append(("Integrity", "no verificada (usa --verify)"))
    width = max(len(k) for k, _ in fields) + 2
    for k, v in fields:
        print(f"{k + ':':<{width}}{v}")
    return 0 if "FAILED" not in fields[-1][1] else 1


def cmd_status(args) -> int:
    cfg = _load(args)
    rows = _file_rows(cfg)
    count = lambda s: sum(r["status"] == s for r in rows)  # noqa: E731
    fields = [
        ("Root", str(cfg.root)),
        ("Watch dir", cfg.watch_dir + "/"),
        ("Output dir", cfg.output_dir + "/"),
        ("Max file size", human_size(cfg.max_file_size)),
        ("Oversize action", cfg.oversize_action),
        ("Settle seconds", f"{cfg.settle_seconds:g}"),
        ("Watch mode", "eventos (watchdog)" if watcher.HAS_WATCHDOG else "polling (watchdog no instalado)"),
        ("Encrypted", str(count("Encrypted"))),
        ("Pending", str(count("Pending"))),
        ("Oversize", str(count("Oversize"))),
        ("Quarantined", str(count("Quarantined"))),
    ]
    if count("Invalid"):
        fields.append(("Invalid", str(count("Invalid"))))
    width = max(len(k) for k, _ in fields) + 2
    for k, v in fields:
        print(f"{k + ':':<{width}}{v}")
    return 0


# clave CLI -> (atributo, parser, formateador)
CONFIG_KEYS = {
    "watch-dir": ("watch_dir", lambda v: v.strip("/"), str),
    "output-dir": ("output_dir", lambda v: v.strip("/"), str),
    "max-size": ("max_file_size", parse_size, human_size),
    "oversize-action": ("oversize_action", None, str),
    "settle-seconds": ("settle_seconds", None, lambda v: f"{v:g}"),
}


def _parse_config_value(key: str, value: str):
    if key == "oversize-action":
        if value not in OVERSIZE_ACTIONS:
            raise CliError(f"oversize-action debe ser uno de: {', '.join(OVERSIZE_ACTIONS)}")
        return value
    if key == "settle-seconds":
        v = float(value)
        if v < 0:
            raise CliError("settle-seconds no puede ser negativo")
        return v
    return CONFIG_KEYS[key][1](value)


def cmd_config(args) -> int:
    cfg = _load(args)
    if args.config_cmd == "view":
        data = asdict(cfg)
        data["root"] = str(cfg.root)
        if not args.raw:
            data["wrapped_key"] = "REDACTED"
            data["kdf"] = {**cfg.kdf, "salt": "REDACTED"}
        print(json.dumps(data, indent=2))
        return 0
    if args.key not in CONFIG_KEYS:
        raise CliError(f"clave desconocida {args.key!r}; válidas: {', '.join(CONFIG_KEYS)}")
    attr, _, fmt = CONFIG_KEYS[args.key]
    if args.config_cmd == "get":
        print(fmt(getattr(cfg, attr)))
        return 0
    old = getattr(cfg, attr)
    setattr(cfg, attr, _parse_config_value(args.key, args.value))
    validate_dirs(cfg.watch_dir, cfg.output_dir)
    cfg.save()
    if args.key in ("watch-dir", "output-dir"):
        write_gitignore(cfg)
        if args.key == "watch-dir":
            cfg.watch_path.mkdir(parents=True, exist_ok=True)
            (cfg.watch_path / ".gitkeep").touch()
            print(f"aviso: los archivos de {old}/ no se mueven; muévelos tú si quieres", file=sys.stderr)
    print(f"{args.key} = {fmt(getattr(cfg, attr))}")
    return 0


def cmd_passwd(args) -> int:
    cfg = _load(args)
    dek = _unlock(cfg, args)
    new = os.environ.get(ENV_NEW_PASSWORD) or _ask_password("Nueva contraseña: ", confirm=True)
    _check_strength(new)
    cfg.set_password(new, dek)
    cfg.save()
    print("contraseña actualizada (los archivos existentes siguen siendo válidos)")
    return 0


def cmd_version(args) -> int:
    print(f"cryptctl {__version__}")
    return 0


COMPLETION_BASH = r"""
_cryptctl() {
  local cur prev words cword
  cur="${COMP_WORDS[COMP_CWORD]}"
  local cmds="init watch encrypt decrypt get describe status config passwd version completion"
  case "${COMP_WORDS[1]}" in
    get)      [ $COMP_CWORD -eq 2 ] && COMPREPLY=($(compgen -W "files" -- "$cur")) && return;;
    describe) [ $COMP_CWORD -eq 2 ] && COMPREPLY=($(compgen -W "file" -- "$cur")) && return;;
    config)
      if [ $COMP_CWORD -eq 2 ]; then COMPREPLY=($(compgen -W "view get set" -- "$cur")); return; fi
      if [ $COMP_CWORD -eq 3 ]; then
        COMPREPLY=($(compgen -W "watch-dir output-dir max-size oversize-action settle-seconds" -- "$cur")); return
      fi;;
    completion) COMPREPLY=($(compgen -W "bash zsh" -- "$cur")); return;;
  esac
  if [ $COMP_CWORD -eq 1 ]; then COMPREPLY=($(compgen -W "$cmds" -- "$cur")); return; fi
  COMPREPLY=($(compgen -f -- "$cur"))
}
complete -o filenames -F _cryptctl cryptctl
"""


def cmd_completion(args) -> int:
    if args.shell == "zsh":
        print("autoload -U +X bashcompinit && bashcompinit")
    print(COMPLETION_BASH.strip())
    return 0


# --- parser --------------------------------------------------------------------

EXAMPLES = """\
ejemplos:
  cryptctl init                      # define la contraseña y crea vault/
  cryptctl watch                     # cifra automáticamente todo lo que llegue a vault/
  cryptctl get files                 # lista archivos y su estado
  cryptctl decrypt informe.pdf       # -> decrypted/informe.pdf
  cryptctl decrypt --all             # descifra todo a decrypted/
  cryptctl config set max-size 250MB
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cryptctl",
        description="Cifra automáticamente lo que se sube a una carpeta del repo.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--root", help="raíz del proyecto (por defecto se busca .cryptctl/ hacia arriba)")
    p.add_argument("--password-file", help=f"leer la contraseña de un archivo (o usa ${ENV_PASSWORD})")
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND", required=True)

    s = sub.add_parser("init", help="inicializa el proyecto y define la contraseña")
    s.add_argument("--dir", default="vault", help="carpeta a vigilar (default: vault)")
    s.add_argument("--max-size", default="100MB", help="tamaño máximo por archivo (default: 100MB)")
    s.add_argument("--force", action="store_true", help="reinicializar aunque ya exista (genera clave NUEVA)")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("watch", help="vigila la carpeta y cifra lo que llegue")
    s.add_argument("--poll", action="store_true", help="forzar polling en vez de eventos del sistema")
    s.add_argument("--interval", type=float, default=1.0, help="segundos entre escaneos en modo polling")
    s.set_defaults(func=cmd_watch)

    s = sub.add_parser("encrypt", help="cifra ahora los archivos pendientes (una sola pasada)")
    s.add_argument("paths", nargs="*", help="archivos concretos (default: todos los pendientes)")
    s.set_defaults(func=cmd_encrypt)

    s = sub.add_parser("decrypt", help="descifra archivos")
    s.add_argument("paths", nargs="*", help="archivos .enc (ruta, o nombre dentro de la carpeta vigilada)")
    s.add_argument("--all", action="store_true", help="descifrar todos")
    s.add_argument("-o", "--output", help="carpeta de salida (default: decrypted/) o '-' para stdout")
    s.add_argument("--force", action="store_true", help="sobrescribir si ya existe")
    s.set_defaults(func=cmd_decrypt)

    s = sub.add_parser("get", help="lista recursos")
    s.add_argument("resource", choices=["files", "file", "f"])
    s.add_argument("-o", "--output", choices=["table", "wide", "json"], default="table")
    s.set_defaults(func=cmd_get)

    s = sub.add_parser("describe", help="muestra detalles de un archivo cifrado")
    s.add_argument("resource", choices=["file", "files", "f"])
    s.add_argument("path")
    s.add_argument("--verify", action="store_true", help="comprobar integridad descifrando (pide contraseña)")
    s.set_defaults(func=cmd_describe)

    s = sub.add_parser("status", help="resumen del proyecto")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("config", help="ver o cambiar la configuración")
    csub = s.add_subparsers(dest="config_cmd", metavar="ACTION", required=True)
    c = csub.add_parser("view", help="muestra la configuración")
    c.add_argument("--raw", action="store_true", help="no ocultar la clave envuelta")
    c = csub.add_parser("get", help="muestra un valor")
    c.add_argument("key", help=", ".join(CONFIG_KEYS))
    c = csub.add_parser("set", help="cambia un valor")
    c.add_argument("key", help=", ".join(CONFIG_KEYS))
    c.add_argument("value")
    s.set_defaults(func=cmd_config)

    s = sub.add_parser("passwd", help=f"cambia la contraseña (no re-cifra nada; o usa ${ENV_NEW_PASSWORD})")
    s.set_defaults(func=cmd_passwd)

    s = sub.add_parser("version", help="muestra la versión")
    s.set_defaults(func=cmd_version)

    s = sub.add_parser("completion", help="script de autocompletado (bash|zsh)")
    s.add_argument("shell", choices=["bash", "zsh"])
    s.set_defaults(func=cmd_completion)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (CliError, ConfigError, crypto.CryptoError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"error: {e.strerror or e}: {e.filename or ''}".rstrip(": "), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
