#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
./scripts/offensive-prepare.sh
docker compose --env-file .local-runtime/offensive/lab.env -f docker-compose.offensive-lab.yml up -d --build --wait --wait-timeout 300
./scripts/local-start.sh
printf '\nOpen http://localhost:8787/offensive/assessments/\ncrAPI: http://localhost:18888/ (mail: http://localhost:18025/)\n'
