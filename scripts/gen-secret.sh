#!/usr/bin/env bash
set -euo pipefail

bytes=${1:-48}

if command -v openssl >/dev/null 2>&1; then
  openssl rand -base64 "$bytes"
else
  # Fallback via Python
  python - <<PY
import os, base64
print(base64.b64encode(os.urandom(${bytes})).decode())
PY
fi


