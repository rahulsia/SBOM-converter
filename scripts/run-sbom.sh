#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Rahul Kumar <rahulk.3477@gmail.com>
# SPDX-License-Identifier: MIT
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p input output

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is required. Install Docker Desktop or Docker Engine." >&2
  exit 127
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose v2 is required." >&2
  exit 127
fi

INPUT_FILE="${SBOM_FILE:-}"
if [[ -z "$INPUT_FILE" ]]; then
  mapfile -t candidates < <(find input -maxdepth 1 -type f \( -name '*.json' -o -name '*.cdx' -o -name '*.spdx' \) -print | sort)
  if (( ${#candidates[@]} == 0 )); then
    echo "ERROR: Put an SBOM JSON file in ./input or set SBOM_FILE." >&2
    exit 2
  fi
  if (( ${#candidates[@]} > 1 )); then
    echo "ERROR: More than one SBOM found. Set SBOM_FILE to select one:" >&2
    printf '  %s\n' "${candidates[@]}" >&2
    exit 2
  fi
  INPUT_FILE="${candidates[0]}"
fi

if [[ "$INPUT_FILE" == /* ]]; then
  CONTAINER_INPUT="$INPUT_FILE"
else
  INPUT_ABS="$(cd "$(dirname "$INPUT_FILE")" && pwd)/$(basename "$INPUT_FILE")"
  case "$INPUT_ABS" in
    "$ROOT_DIR/input/"*) CONTAINER_INPUT="/data/input/${INPUT_ABS#"$ROOT_DIR/input/"}" ;;
    *) echo "ERROR: SBOM_FILE must point to a file under ./input." >&2; exit 2 ;;
  esac
fi

UID_VALUE="$(id -u)"
GID_VALUE="$(id -g)"
export NVD_API_KEY="${NVD_API_KEY:-}"

run() {
  docker compose run --rm --user "$UID_VALUE:$GID_VALUE" sbom-convert "$@"
}

BASE="$(basename "$INPUT_FILE")"
NAME="${BASE%.*}"

echo "==> Input: $INPUT_FILE"
run "$CONTAINER_INPUT" --info

echo "==> SPDX 2.3/CycloneDX conversion: CycloneDX 1.7"
run "$CONTAINER_INPUT" --to cdx-1.7   --report "/data/output/${NAME}.cdx-conversion.json"   -o "/data/output/${NAME}.cdx-1.7.json"

echo "==> Conversion: SPDX 3.0.1"
run "$CONTAINER_INPUT" --to spdx-3.0.1   --report "/data/output/${NAME}.spdx3-conversion.json"   -o "/data/output/${NAME}.spdx-3.0.1.json"

echo "==> Vulnerability scan: OSV + NVD"
run "$CONTAINER_INPUT"   --vuln-source both   --osv-report "/data/output/${NAME}.osv.json"   --nvd-report "/data/output/${NAME}.nvd.json"   --security-report "/data/output/${NAME}.security.json"

echo "==> Generate OpenVEX from discovered findings"
run "$CONTAINER_INPUT"   --vuln-source both   --vex   --vex-output "/data/output/${NAME}.vex.json"

echo
echo "Completed. Reports are in ./output/"
