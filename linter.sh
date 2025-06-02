#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $(basename "$0") [check|format]" >&2
  exit 1
}

ACTION="${1:-check}"

case "$ACTION" in
  check)
    CMD=(lint . --parallel --recursive --strict)
    ;;
  format)
    CMD=(format . --parallel --recursive -i)
    ;;
  -h|--help)
    usage
    ;;
  *)
    echo "Invalid argument: $ACTION" >&2
    usage
    ;;
esac

exec xcrun swift-format "${CMD[@]}"
