#!/usr/bin/env bash
SHARED_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "$SHARED_DIR/constants.bash"
source "$SHARED_DIR/credentials.bash"
source "$SHARED_DIR/assertions.bash"
source "$SHARED_DIR/piv_helpers.bash"
source "$SHARED_DIR/crypto_helpers.bash"

common_setup() {
    export TEST_TMP_DIR="${BATS_TEST_TMPDIR:?BATS temporary directory is required}"
    if [[ "${PIV_TOOL_DESTRUCTIVE_TESTS:-}" != "1" ]]; then
        skip "Set PIV_TOOL_DESTRUCTIVE_TESTS=1 to allow PIV reset and key replacement on a dedicated test YubiKey"
    fi
    mkdir -p "$TEST_TMP_DIR"
    check_yubikey_connected
    check_openssl_available
}

common_teardown() {
    [[ -n "$TEST_TMP_DIR" ]] || return 0
    rm -rf "$TEST_TMP_DIR"/*
}