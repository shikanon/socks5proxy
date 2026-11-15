#!/bin/bash
# Codex-only proxy launcher. Does not export anything into the caller shell or launchd.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "$0")" && pwd)"
PYTHON=""
for candidate in "$HOME/Library/Application Support/DoubaoWork/sandbox_runtime/bases/"*/bin/python3; do
  if [ -x "$candidate" ]; then PYTHON="$candidate"; break; fi
done
if [ -z "$PYTHON" ]; then PYTHON="$(command -v python3 || true)"; fi
if [ -z "$PYTHON" ]; then printf '%s\n' 'Python 3 is required.' >&2; exit 1; fi
exec "$PYTHON" "$ROOT/scripts/codex-proxy-launch.py" "$@"
