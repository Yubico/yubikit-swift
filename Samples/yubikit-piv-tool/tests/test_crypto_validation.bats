#!/usr/bin/env bats

load 'shared/setup'
load 'shared/crypto_helpers'

setup() {
    common_setup
    check_openssl_available
    reset_piv_to_factory
}

teardown() {
    common_teardown
}

@test "Crypto: Validate RSA key generation" {
    show_test_section "Testing RSA cryptographic operations"
    
    local pubkey_file="$TEST_TMP_DIR/rsa_pubkey.pem"
    local cert_file="$TEST_TMP_DIR/rsa_cert.pem"
    
    run generate_test_key "$SLOT_SIGN" "$ALG_RSA" "$pubkey_file"
    assert_success
    
    run piv_tool certificates generate "$SLOT_SIGN" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates export "$SLOT_SIGN" "$cert_file"
    assert_success
    
    validate_public_key_pem "$pubkey_file" || fail "RSA public key validation failed"
    validate_certificate_pem "$cert_file" || fail "RSA certificate validation failed"
    
    verify_certificate_key_match "$cert_file" "$pubkey_file" || fail "Certificate-key pair validation failed"
    
    local algorithm key_size
    algorithm=$(get_certificate_algorithm "$cert_file")
    [[ "$algorithm" =~ "rsaEncryption" ]] || fail "Certificate should use rsaEncryption: $algorithm"
}

@test "Crypto: Validate ECC key generation and certificate properties" {
    show_test_section "Testing ECC cryptographic operations"
    
    local pubkey_file="$TEST_TMP_DIR/ecc_pubkey.pem"
    local cert_file="$TEST_TMP_DIR/ecc_cert.pem" 
    local csr_file="$TEST_TMP_DIR/ecc_csr.pem"
    
    run generate_test_key "$SLOT_AUTH" "$ALG_ECC" "$pubkey_file"
    assert_success
    
    run piv_tool certificates generate "$SLOT_AUTH" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates export "$SLOT_AUTH" "$cert_file"
    assert_success
    
    run piv_tool certificates request "$SLOT_AUTH" "$csr_file" \
        --pin "$DEFAULT_PIN"
    assert_success
    
    validate_public_key_pem "$pubkey_file" || fail "ECC public key validation failed"
    validate_certificate_pem "$cert_file" || fail "ECC certificate validation failed"
    validate_csr_pem "$csr_file" || fail "ECC CSR validation failed"
    
    local key_size cert_algorithm
    key_size=$(get_key_size "$pubkey_file")
    cert_algorithm=$(get_certificate_algorithm "$cert_file")
    
    [[ "$key_size" == "256" ]] || fail "Expected 256-bit ECC key, got: $key_size"
    [[ "$cert_algorithm" =~ "id-ecPublicKey" ]] || fail "Certificate should use id-ecPublicKey: $cert_algorithm"
    
    local cert_pubkey="$TEST_TMP_DIR/cert_pubkey.pem"
    local csr_pubkey="$TEST_TMP_DIR/csr_pubkey.pem"
    
    openssl x509 -in "$cert_file" -noout -pubkey > "$cert_pubkey" 2>/dev/null
    openssl req -in "$csr_file" -noout -pubkey > "$csr_pubkey" 2>/dev/null
    
    local orig_hash cert_hash csr_hash
    orig_hash=$(openssl pkey -pubin -in "$pubkey_file" -outform DER 2>/dev/null | openssl dgst -sha256)
    cert_hash=$(openssl pkey -pubin -in "$cert_pubkey" -outform DER 2>/dev/null | openssl dgst -sha256)
    csr_hash=$(openssl pkey -pubin -in "$csr_pubkey" -outform DER 2>/dev/null | openssl dgst -sha256)
    
    [[ "$orig_hash" == "$cert_hash" ]] || fail "Certificate public key doesn't match original"
    [[ "$orig_hash" == "$csr_hash" ]] || fail "CSR public key doesn't match original"
}

@test "Crypto: Validate certificate import/export integrity" {
    show_test_section "Testing certificate import/export cryptographic integrity"
    
    local pubkey_file="$TEST_TMP_DIR/pubkey.pem"
    local original_cert="$TEST_TMP_DIR/original_cert.pem"
    local exported_cert="$TEST_TMP_DIR/exported_cert.pem"
    local reimported_cert="$TEST_TMP_DIR/reimported_cert.pem"
    
    run generate_test_key "$SLOT_KEYMGMT" "$ALG_RSA" "$pubkey_file"
    assert_success
    
    run piv_tool certificates generate "$SLOT_KEYMGMT" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates export "$SLOT_KEYMGMT" "$original_cert"
    assert_success
    
    run piv_tool certificates export "$SLOT_KEYMGMT" "$exported_cert"
    assert_success
    
    # Delete and reimport
    run piv_tool certificates delete "$SLOT_KEYMGMT" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates import "$SLOT_KEYMGMT" "$exported_cert" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_success
    
    run piv_tool certificates export "$SLOT_KEYMGMT" "$reimported_cert"
    assert_success
    
    validate_certificate_pem "$original_cert" || fail "Original certificate validation failed"
    validate_certificate_pem "$exported_cert" || fail "Exported certificate validation failed"
    validate_certificate_pem "$reimported_cert" || fail "Reimported certificate validation failed"
    
    local orig_hash exported_hash reimported_hash
    orig_hash=$(openssl x509 -in "$original_cert" -outform DER 2>/dev/null | openssl dgst -sha256)
    exported_hash=$(openssl x509 -in "$exported_cert" -outform DER 2>/dev/null | openssl dgst -sha256)  
    reimported_hash=$(openssl x509 -in "$reimported_cert" -outform DER 2>/dev/null | openssl dgst -sha256)
    
    [[ "$orig_hash" == "$exported_hash" ]] || fail "Exported certificate differs from original"
    [[ "$exported_hash" == "$reimported_hash" ]] || fail "Reimported certificate differs from exported"
    
    verify_certificate_key_match "$original_cert" "$pubkey_file" || fail "Original certificate doesn't match key"
    verify_certificate_key_match "$exported_cert" "$pubkey_file" || fail "Exported certificate doesn't match key"
    verify_certificate_key_match "$reimported_cert" "$pubkey_file" || fail "Reimported certificate doesn't match key"
}
