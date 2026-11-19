#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly SCRIPT_DIR

usage() {
  cat <<EOF
Usage: $(basename "$0") <hardware|twinkit[=PROFILE]> [test-options]

  hardware           Run macOS scenarios against an allow-listed YubiKey.
  twinkit[=PROFILE]  Run macOS scenarios with TwinKit. Extra options go to Xcode.

Environment knobs (passed through):
  YUBIKIT_TWINKIT_TRANSPORT=nfc   Drive the run contactless. CCID becomes the only
                                  path: the OTP keyboard and FIDO HID interfaces
                                  are USB-only, so those scenarios skip.
  YUBIKIT_TWIN_PATH=<dir>         Resolve TwinKit from a local hardware-digital-twin
                                  checkout instead of the published package, so twin
                                  changes are testable before they are pushed. SwiftPM
                                  takes the package identity from the directory name,
                                  so <dir> must be named hardware-digital-twin.
  SCENARIO=<id substring>         Run only the scenarios whose id contains the substring,
                                  e.g. SCENARIO=PIV.Signatures for a whole family.
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
    exec env -u YUBIKIT_REQUIRE_VIRTUAL_KEY \
      swift test --package-path "$SCRIPT_DIR/IntegrationTesting" \
      --scratch-path "$SCRIPT_DIR/.build/scenarios-hardware" --filter IntegrationTests "$@"
    ;;
  twinkit|twinkit=*)
    profile=5-nfc
    if [[ "$BACKEND" == twinkit=* ]]; then profile="${BACKEND#twinkit=}"; fi
    transport=$(printf '%s' "${YUBIKIT_TWINKIT_TRANSPORT:-usb}" | tr '[:upper:]' '[:lower:]')
    exec "$SCRIPT_DIR/IntegrationTesting/Simulated/run-sdk.sh" scenarios \
      --profile "$profile" --transport "$transport" -- "$@"
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
