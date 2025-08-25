#!/usr/bin/env bats

load 'shared/setup'
load 'shared/crypto_helpers'

setup() {
    common_setup
    reset_piv_to_factory
}

teardown() {
    common_teardown
}

@test "Certificates: Generate self-signed certificate for existing key" {
    show_test_section "Testing self-signed certificate generation"
    
    local pubkey_file="$TEST_TMP_DIR/pubkey.pem"
    local cert_file="$TEST_TMP_DIR/cert.pem"
    
    run generate_test_key "$SLOT_AUTH" "$ALG_RSA" "$pubkey_file"
    assert_success
    
    run piv_tool certificates generate "$SLOT_AUTH" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates export "$SLOT_AUTH" "$cert_file"
    assert_success
    
    assert_file_exists "$cert_file"
    validate_certificate_pem "$cert_file" || fail "Generated certificate is invalid"
    
    local subject algorithm
    subject=$(get_certificate_subject "$cert_file")
    algorithm=$(get_certificate_algorithm "$cert_file")
    
    [[ "$subject" =~ "CN=Yubikit" ]] || fail "Certificate subject incorrect: $subject"
    [[ "$algorithm" =~ "rsaEncryption" ]] || fail "Certificate algorithm should be rsaEncryption: $algorithm"
    
    verify_certificate_key_match "$cert_file" "$pubkey_file" || fail "Certificate does not match public key"
}

@test "Certificates: Export certificate from slot" {
    show_test_section "Testing certificate export"
    
    local pubkey_file="$TEST_TMP_DIR/pubkey.pem"
    local cert_file="$TEST_TMP_DIR/cert.pem"
    local exported_cert="$TEST_TMP_DIR/exported.pem"
    
    # Generate key and certificate first
    run generate_test_key "$SLOT_SIGN" "$ALG_ECC" "$pubkey_file"
    assert_success
    
    run piv_tool certificates generate "$SLOT_SIGN" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates export "$SLOT_SIGN" "$cert_file"
    assert_success
    
    run piv_tool certificates export "$SLOT_SIGN" "$exported_cert"
    assert_success
    
    assert_file_exists "$exported_cert"
    validate_certificate_pem "$exported_cert" || fail "Exported certificate is invalid"
    
    local orig_subject exported_subject
    orig_subject=$(get_certificate_subject "$cert_file")
    exported_subject=$(get_certificate_subject "$exported_cert")
    
    [[ "$orig_subject" == "$exported_subject" ]] || fail "Exported certificate subject doesn't match original"
}

@test "Certificates: Import external certificate" {
    show_test_section "Testing certificate import"
    
    local pubkey_file="$TEST_TMP_DIR/pubkey.pem"
    local cert_file="$TEST_TMP_DIR/cert.pem"
    local imported_cert="$TEST_TMP_DIR/imported.pem"
    
    # Generate key and certificate
    run generate_test_key "$SLOT_KEYMGMT" "$ALG_RSA" "$pubkey_file"
    assert_success
    
    run piv_tool certificates generate "$SLOT_KEYMGMT" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    # Export certificate for testing
    run piv_tool certificates export "$SLOT_KEYMGMT" "$cert_file"
    assert_success
    
    # Delete existing certificate
    run piv_tool certificates delete "$SLOT_KEYMGMT" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates import "$SLOT_KEYMGMT" "$cert_file" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    # Verify import worked by exporting again
    run piv_tool certificates export "$SLOT_KEYMGMT" "$imported_cert"
    assert_success
    
    assert_file_exists "$imported_cert"
    validate_certificate_pem "$imported_cert" || fail "Imported certificate is invalid"
    
    local orig_subject imported_subject
    orig_subject=$(get_certificate_subject "$cert_file")
    imported_subject=$(get_certificate_subject "$imported_cert")
    
    [[ "$orig_subject" == "$imported_subject" ]] || fail "Imported certificate doesn't match original"
}

@test "Certificates: Delete certificate from slot" {
    show_test_section "Testing certificate deletion"
    
    local pubkey_file="$TEST_TMP_DIR/pubkey.pem"
    local cert_file="$TEST_TMP_DIR/cert.pem"
    
    # Generate key and certificate first
    run generate_test_key "$SLOT_AUTH" "$ALG_ECC" "$pubkey_file"
    assert_success
    
    run piv_tool certificates generate "$SLOT_AUTH" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    # Verify certificate exists
    run piv_tool certificates export "$SLOT_AUTH" "$TEST_TMP_DIR/before_delete.pem"
    assert_success
    
    # Delete certificate (key remains)
    run piv_tool certificates delete "$SLOT_AUTH" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    # Verify certificate is gone (export should fail)
    run piv_tool certificates export "$SLOT_AUTH" "$TEST_TMP_DIR/after_delete.pem"
    assert_failure
    
    # Key should still exist
    run piv_tool certificates generate "$SLOT_AUTH" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates export "$SLOT_AUTH" "$TEST_TMP_DIR/new_cert.pem"
    assert_success
    
    assert_file_exists "$TEST_TMP_DIR/new_cert.pem"
    validate_certificate_pem "$TEST_TMP_DIR/new_cert.pem" || fail "New certificate after deletion is invalid"
}

@test "Certificates: Generate Certificate Signing Request (CSR)" {
    show_test_section "Testing CSR generation"
    
    local pubkey_file="$TEST_TMP_DIR/pubkey.pem"
    local csr_file="$TEST_TMP_DIR/request.csr"
    
    run generate_test_key "$SLOT_SIGN" "$ALG_RSA" "$pubkey_file"
    assert_success
    
    run piv_tool certificates request "$SLOT_SIGN" "$csr_file" \
        --pin "$DEFAULT_PIN"
    assert_success
    
    assert_file_exists "$csr_file"
    validate_csr_pem "$csr_file" || fail "Generated CSR is invalid"
    
    local csr_pubkey="$TEST_TMP_DIR/csr_pubkey.pem"
    openssl req -in "$csr_file" -noout -pubkey > "$csr_pubkey" 2>/dev/null
    
    local orig_hash csr_hash
    orig_hash=$(openssl pkey -pubin -in "$pubkey_file" -outform DER 2>/dev/null | openssl dgst -sha256)
    csr_hash=$(openssl pkey -pubin -in "$csr_pubkey" -outform DER 2>/dev/null | openssl dgst -sha256)
    
    [[ "$orig_hash" == "$csr_hash" ]] || fail "CSR public key doesn't match generated key"
}
