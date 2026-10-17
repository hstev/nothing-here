#!/usr/bin/env bash
# Instala cryptctl y, si el proyecto no está inicializado, define la contraseña.
set -euo pipefail
cd "$(dirname "$0")"

if command -v pipx >/dev/null 2>&1; then
  pipx install --force .
else
  python3 -m pip install --user .
fi

if ! command -v cryptctl >/dev/null 2>&1; then
  echo "cryptctl instalado, pero no está en el PATH (revisa ~/.local/bin)" >&2
  exit 1
fi

if [ ! -f .cryptctl/config.json ]; then
  cryptctl init "$@"
else
  echo "proyecto ya inicializado: $(pwd)/.cryptctl/config.json"
fi

echo
echo "autocompletado (opcional): añade a tu ~/.zshrc o ~/.bashrc:"
echo "  source <(cryptctl completion ${SHELL##*/})"
