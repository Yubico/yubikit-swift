#!/usr/bin/env bats

load 'shared/setup'

setup() {
    common_setup
    reset_piv_to_factory
}

teardown() {
    common_teardown
}

@test "Access: Change PIN from default to custom" {
    show_test_section "Testing PIN change operation"
    
    run piv_tool access change-pin \
        --pin "$DEFAULT_PIN" \
        --new-pin "$TEST_PIN"
    assert_success
    
    # Old PIN should fail
    run piv_tool access change-pin \
        --pin "$DEFAULT_PIN" \
        --new-pin "999999"
    assert_failure
    
    # New PIN should work
    run piv_tool access change-pin \
        --pin "$TEST_PIN" \
        --new-pin "$DEFAULT_PIN"
    assert_success
    
    # Verify we can use default PIN again
    run piv_tool access change-pin \
        --pin "$DEFAULT_PIN" \
        --new-pin "$TEST_PIN"
    assert_success
}

@test "Access: Change PUK from default to custom" {
    show_test_section "Testing PUK change operation"
    
    run piv_tool access change-puk \
        --puk "$DEFAULT_PUK" \
        --new-puk "$TEST_PUK"
    assert_success
    
    # Block PIN with wrong attempts
    run piv_tool access change-pin --pin "111111" --new-pin "$TEST_PIN" 2>/dev/null || true
    run piv_tool access change-pin --pin "222222" --new-pin "$TEST_PIN" 2>/dev/null || true
    run piv_tool access change-pin --pin "333333" --new-pin "$TEST_PIN" 2>/dev/null || true
    
    # Try to unblock with old PUK (should fail)
    run piv_tool access unblock-pin \
        --puk "$DEFAULT_PUK" \
        --new-pin "$TEST_PIN"
    assert_failure
    
    # Unblock with new PUK (should work)
    run piv_tool access unblock-pin \
        --puk "$TEST_PUK" \
        --new-pin "$TEST_PIN"
    assert_success
    
    # Verify PIN was unblocked and set correctly
    run piv_tool access change-pin \
        --pin "$TEST_PIN" \
        --new-pin "$DEFAULT_PIN"
    assert_success
}

@test "Access: Change management key from default to custom" {
    show_test_section "Testing management key change"
    
    run piv_tool access change-management-key \
        --management-key "$DEFAULT_MGMT_KEY" \
        --new-management-key "$TEST_MGMT_KEY"
    assert_success
    
    # Try with old management key (should fail)
    local pubkey_file="$TEST_TMP_DIR/test_pubkey.pem"
    run piv_tool keys generate "$SLOT_AUTH" "$pubkey_file" \
        --algorithm "$ALG_RSA" \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    assert_failure
    
    # Verify new management key works
    run piv_tool keys generate "$SLOT_AUTH" "$pubkey_file" \
        --algorithm "$ALG_RSA" \
        --pin "$DEFAULT_PIN" \
        --management-key "$TEST_MGMT_KEY"
    assert_success
    
    # Verify key was generated successfully
    assert_file_exists "$pubkey_file"
}

@test "Access: Unblock PIN using PUK" {
    show_test_section "Testing PIN unblock operation"
    
    # Block PIN
    run piv_tool access change-pin --pin "111111" --new-pin "$TEST_PIN" 2>/dev/null || true
    run piv_tool access change-pin --pin "222222" --new-pin "$TEST_PIN" 2>/dev/null || true  
    run piv_tool access change-pin --pin "333333" --new-pin "$TEST_PIN" 2>/dev/null || true
    
    # Verify PIN is blocked (should fail with correct PIN)
    run piv_tool access change-pin --pin "$DEFAULT_PIN" --new-pin "$TEST_PIN"
    assert_failure
    
    # Unblock PIN using PUK
    run piv_tool access unblock-pin \
        --puk "$DEFAULT_PUK" \
        --new-pin "$TEST_PIN"
    assert_success
    
    # Verify PIN was unblocked and set to new value
    run piv_tool access change-pin \
        --pin "$TEST_PIN" \
        --new-pin "$DEFAULT_PIN"
    assert_success
    
    # Verify we can use the default PIN again
    run piv_tool access change-pin \
        --pin "$DEFAULT_PIN" \
        --new-pin "$TEST_PIN"
    assert_success
}

@test "Access: Verify info command shows retry counts correctly" {
    show_test_section "Testing PIN/PUK retry count display"
    
    run piv_tool info
    assert_success
    
    assert_output_contains "PIN tries remaining: 3/3"
    assert_output_contains "PUK tries remaining: 3/3"
    
    # Use wrong PIN once
    run piv_tool access change-pin --pin "000000" --new-pin "$TEST_PIN" 2>/dev/null || true
    
    # Check retry count decreased
    run piv_tool info  
    assert_success
    
    assert_output_contains "PIN tries remaining: 2/3"
    
    # Reset to clean state for other tests
    reset_piv_to_factory
}