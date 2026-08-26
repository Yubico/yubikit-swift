#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR

usage() {
  cat <<EOF
Usage: $(basename "$0") <hardware|twinkit[=PROFILE]> [swift-test-options]

  hardware           Run macOS scenarios against an allow-listed YubiKey.
  twinkit[=PROFILE]  Run scenarios using a Yubico-internal test tool.
EOF
}

BACKEND="${1:-}"
if [[ -z "$BACKEND" ]]; then
  usage >&2
  exit 1
fi
shift

case "$BACKEND" in
  hardware)
    if [[ -z "${YUBIKEY_TEST_SERIALS:-}" ]]; then
      echo "YUBIKEY_TEST_SERIALS must contain at least one YubiKey serial." >&2
      exit 1
    fi
    if [[ ! "$YUBIKEY_TEST_SERIALS" =~ ^[[:space:]]*[[:digit:]]+([[:space:],]+[[:digit:]]+)*[[:space:]]*$ ]]; then
      echo "YUBIKEY_TEST_SERIALS must contain positive decimal serials separated by commas or spaces." >&2
      exit 1
    fi
    cat >&2 <<EOF
WARNING: Integration scenarios may reset applications and overwrite data.
Only run them against dedicated test YubiKeys listed in YUBIKEY_TEST_SERIALS.
EOF
    cd "$SCRIPT_DIR"
    exec env -u YUBIKIT_ENABLE_TWINKIT \
      swift test --scratch-path .build/scenarios-hardware --filter IntegrationTests "$@"
    ;;
  twinkit)
    PROFILE="5-nfc"
    ;;
  twinkit=*)
    PROFILE="${BACKEND#twinkit=}"
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    echo "Invalid backend: $BACKEND" >&2
    usage >&2
    exit 1
    ;;
esac

case "$PROFILE" in
  5-nfc|5c-nfc|5-nano|5c-nano|5-fips|bio-mpe|bio-fido|sky-nfc)
    ;;
  "")
    echo "Internal profile must not be empty." >&2
    usage >&2
    exit 1
    ;;
  *)
    echo "Invalid internal profile: $PROFILE" >&2
    usage >&2
    exit 1
    ;;
esac

cd "$SCRIPT_DIR"
exec env YUBIKIT_ENABLE_TWINKIT="$PROFILE" \
  swift test --scratch-path .build/scenarios-twinkit --filter IntegrationTests "$@"
