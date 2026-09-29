#!/usr/bin/env bash
# wrapper maroto do bit2
# se der ruim no python, pelo menos avisa direito

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

# chega se tem python
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "erro: nao achei $PY no PATH" >&2
    exit 1
fi

# checa versao minima
ver=$("$PY" -c 'import sys;print("%d%02d"%sys.version_info[:2])')
if [ "$ver" -lt 308 ]; then
    echo "erro: precisa de python 3.8+" >&2
    exit 1
fi

exec "$PY" "$DIR/bit2.py" "$@"
