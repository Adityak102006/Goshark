#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/.venv/bin/goshark" ]; then
    exec "$SCRIPT_DIR/.venv/bin/goshark" "$@"
elif command -v goshark >/dev/null 2>&1; then
    exec goshark "$@"
else
    echo "Error: goshark executable not found. Please run ./install.sh first." >&2
    exit 1
fi
