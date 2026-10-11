#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# Stop only this optional lab. Keep source, evidence and database volumes.
docker compose --env-file .local-runtime/offensive/lab.env -f docker-compose.offensive-lab.yml stop
