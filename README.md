# cryptctl

Cifra automáticamente todo lo que se sube a una carpeta del repo (`vault/`). Solo los `.enc` llegan a git; el texto plano nunca se commitea. Los comandos siguen el estilo de `kubectl`.

```
$ cryptctl watch
2026-10-17 13:02:11 INFO  vigilando vault/ en modo eventos (watchdog); máx 100.0MB, sobretamaño -> quarantine
2026-10-17 13:02:20 INFO  cifrado vault/contrato.pdf -> vault/contrato.pdf.enc (1.3MB)
2026-10-17 13:02:41 WARN  vault/backup.iso (4.2GB) supera 100.0MB: movido a .cryptctl/quarantine/backup.iso SIN cifrar

$ cryptctl get files
NAME                    STATUS        SIZE      AGE
contrato.pdf.enc        Encrypted     1.3MB     21s
quarantine/backup.iso   Quarantined   4.2GB     2s
```

## Instalación

Requiere Python 3.10 o superior.

```bash
./install.sh          # pipx install . + cryptctl init (aquí defines la contraseña)
```

Si prefieres hacerlo a mano: `pipx install .` (o `pip install --user .`) y después `cryptctl init`.

`init` crea:

| Ruta | Qué es | ¿Va a git? |
|---|---|---|
| `.cryptctl/config.json` | configuración + clave de datos **envuelta** con tu contraseña | sí (sin ella no se puede descifrar desde otro clon) |
| `vault/` | carpeta vigilada; solo los `*.enc` se versionan | solo `*.enc` |
| `decrypted/` | salida por defecto de `decrypt` | no |
| `.cryptctl/quarantine/` | archivos demasiado grandes, **sin cifrar** | no |
| bloque en `.gitignore` | reglas para que el texto plano nunca entre a git | sí |

> **Si pierdes la contraseña, no hay forma de recuperar los archivos.**

## Uso

```bash
cryptctl watch                       # deja vigilando; Ctrl+C para salir
cryptctl encrypt                     # una sola pasada: cifra lo pendiente y sale
cryptctl get files [-o wide|json]    # estado: Encrypted / Pending / Oversize / Quarantined
cryptctl describe file contrato.pdf  # detalles del .enc (añade --verify para comprobar integridad)
cryptctl decrypt contrato.pdf        # -> decrypted/contrato.pdf
cryptctl decrypt --all               # descifra todo, conservando subcarpetas
cryptctl decrypt notas.txt -o -      # a stdout
cryptctl status
cryptctl config view
cryptctl config set max-size 250MB
cryptctl config set oversize-action skip   # quarantine | skip | delete
cryptctl passwd                      # cambia la contraseña sin volver a cifrar nada
source <(cryptctl completion zsh)    # autocompletado (bash|zsh)
```

En `decrypt` y `describe` el archivo se puede indicar con su ruta, con la ruta relativa a `vault/`, o sin `.enc`.

### Uso sin interacción (systemd, scripts)

La contraseña se pide por teclado. También se puede pasar con `--password-file FILE` o con la variable `CRYPTCTL_PASSWORD`. Ejemplo de servicio de usuario (`~/.config/systemd/user/cryptctl.service`):

```ini
[Service]
WorkingDirectory=/ruta/al/repo
ExecStart=%h/.local/bin/cryptctl --password-file %h/.config/cryptctl/pass watch
Restart=on-failure
[Install]
WantedBy=default.target
```

## Cómo funciona

- **Detección**: usa eventos del sistema (`watchdog`, inotify) y, además, re-escanea la carpeta cada 30 s por si se pierde algún evento. Sin `watchdog`, o con `--poll`, escanea cada `--interval` segundos.
- **Subidas a medias**: un archivo se cifra solo cuando su tamaño y su fecha de modificación no cambian durante `settle-seconds` (2 s por defecto). Si cambia mientras se cifra, el resultado se descarta y se vuelve a intentar.
- **Archivos pesados**:
  - el cifrado es por streaming en bloques de 64 KiB, así que la memoria usada es constante sea cual sea el tamaño;
  - lo que supera `max-size` (100 MB por defecto) no se cifra y va a cuarentena;
  - si no hay espacio en disco para la copia cifrada, se avisa y se reintenta a los 30 s.
- **Escritura atómica**: el cifrado se escribe en `.<nombre>.enc.part`, se hace fsync y se renombra. El original se borra solo después de eso. Si ya existe `a.txt.enc`, el nuevo archivo se guarda como `a (1).txt.enc`.
- **Qué se ignora**: archivos y carpetas ocultos (`.algo`), `*.enc`, `*.part` y symlinks.

### Criptografía

- `init` genera una clave de datos aleatoria de 256 bits (DEK). La contraseña pasa por **scrypt** (N=2¹⁷, r=8, p=1) y da la KEK, que envuelve la DEK con **AES-256-GCM**. La contraseña no se guarda en ningún sitio.
- Cada archivo usa una clave propia: `HKDF-SHA256(DEK, salt aleatorio)`.
- Formato `.enc`: `CRYPTCTL | versión | chunk_size | salt`, seguido de bloques AES-256-GCM. El nonce de cada bloque es el contador más una marca de "último bloque", y el header va como AAD. Así se detecta cualquier modificación, truncado o reordenamiento de bloques.
- Al descifrar, el resultado se escribe en un temporal y solo se renombra si todo el archivo se autentica.

### Limitaciones

- Borrar el texto plano con `unlink` no lo sobrescribe en el disco: en SSD o en sistemas de archivos con journaling pueden quedar restos recuperables. Si eso te importa, usa cifrado de disco.
- Los archivos en cuarentena siguen **sin cifrar**: revísalos y bórralos o súbelos a otro sitio.
- Con `-o -` (stdout) los datos se emiten mientras se verifican; si el archivo está corrupto, el comando falla, pero la salida ya emitida puede estar incompleta.

## Desarrollo

```bash
python3 -m unittest discover -s tests -t .
python3 -m cryptctl --help
```
