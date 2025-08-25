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

@test "Keys: Generate RSA2048 key pair in authentication slot" {
    show_test_section "Testing RSA2048 key generation"
    
    local pubkey_file="$TEST_TMP_DIR/rsa_pubkey.pem"
    
    run generate_test_key "$SLOT_AUTH" "$ALG_RSA" "$pubkey_file"
    assert_success
    
    assert_file_exists "$pubkey_file"
    validate_public_key_pem "$pubkey_file" || fail "Generated public key is invalid"
    
    local algorithm key_size
    algorithm=$(get_public_key_algorithm "$pubkey_file")
    key_size=$(get_key_size "$pubkey_file")
    
    [[ "$algorithm" == "RSA" ]] || fail "Expected RSA algorithm, got: $algorithm"
    [[ "$key_size" == "2048" ]] || fail "Expected 2048-bit key, got: $key_size"
}

@test "Keys: Generate ECCP256 key pair in signing slot" {
    show_test_section "Testing ECCP256 key generation"
    
    local pubkey_file="$TEST_TMP_DIR/ecc_pubkey.pem"
    
    run generate_test_key "$SLOT_SIGN" "$ALG_ECC" "$pubkey_file"
    assert_success
    
    assert_file_exists "$pubkey_file"
    validate_public_key_pem "$pubkey_file" || fail "Generated public key is invalid"
    
    local algorithm key_size
    algorithm=$(get_public_key_algorithm "$pubkey_file")
    key_size=$(get_key_size "$pubkey_file")
    
    [[ "$algorithm" == "EC" ]] || fail "Expected EC algorithm, got: $algorithm"  
    [[ "$key_size" == "256" ]] || fail "Expected 256-bit ECC key, got: $key_size"
}

@test "Keys: Display key information for generated keys" {
    show_test_section "Testing key info display"
    
    local pubkey_file="$TEST_TMP_DIR/test_pubkey.pem"
    
    run generate_test_key "$SLOT_AUTH" "$ALG_RSA" "$pubkey_file"
    assert_success
    
    run piv_tool keys info "$SLOT_AUTH"
    assert_success
    
    assert_output_contains "Algorithm: RSA2048"
    assert_output_contains "Origin: Generated"
    assert_output_contains "PIN policy: Once"
    
    [[ ! "$output" =~ "Error" ]] && [[ ! "$output" =~ "Failed" ]] && [[ ! "$output" =~ "No key" ]]
}

@test "Keys: Generate attestation certificate" {
    show_test_section "Testing key attestation"
    
    local pubkey_file="$TEST_TMP_DIR/test_pubkey.pem"
    local attest_file="$TEST_TMP_DIR/attestation.pem"
    
    run generate_test_key "$SLOT_KEYMGMT" "$ALG_ECC" "$pubkey_file"
    assert_success
    
    run piv_tool keys attest "$SLOT_KEYMGMT" "$attest_file"
    assert_success
    
    assert_file_exists "$attest_file"
    validate_certificate_pem "$attest_file" || fail "Generated attestation certificate is invalid"
    
    local subject
    subject=$(get_certificate_subject "$attest_file")
    [[ "$subject" =~ "YubiKey PIV Attestation" ]] || fail "Attestation cert should have YubiKey PIV subject: $subject"
    
    local cert_algorithm
    cert_algorithm=$(get_certificate_algorithm "$attest_file")
    [[ "$cert_algorithm" =~ "id-ecPublicKey" ]] || fail "Attestation cert should use ECC algorithm: $cert_algorithm"
}