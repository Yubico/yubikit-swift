#!/usr/bin/env bash
SHARED_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "$SHARED_DIR/constants.bash"
source "$SHARED_DIR/credentials.bash"
source "$SHARED_DIR/assertions.bash"
source "$SHARED_DIR/piv_helpers.bash"
source "$SHARED_DIR/crypto_helpers.bash"

common_setup() {
    mkdir -p "$TEST_TMP_DIR"
    check_yubikey_connected
    check_openssl_available
}

common_teardown() {
    rm -rf "$TEST_TMP_DIR"/*
}