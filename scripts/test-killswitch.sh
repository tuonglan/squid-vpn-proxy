#!/usr/bin/env bash
# Disrupts this project's DEV proxy briefly and always requests a restart.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
if [[ ${1:-} != --disrupt-dev ]]; then
  echo 'Usage: scripts/test-killswitch.sh --disrupt-dev' >&2
  echo 'Deletes the dev container tunnel to verify that traffic cannot bypass it.' >&2
  exit 2
fi
trap './scripts/compose.sh dev restart proxy' EXIT
./scripts/compose.sh dev exec -T proxy python3 /opt/proxy/check_killswitch.py
