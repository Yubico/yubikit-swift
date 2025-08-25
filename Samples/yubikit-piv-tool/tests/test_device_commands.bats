#!/usr/bin/env bats

load 'shared/setup'

setup() {
    common_setup
}

teardown() {
    common_teardown
}

@test "Device: List connected YubiKeys" {
    show_test_section "Testing device enumeration"
    
    run piv_tool list
    assert_success
    
    # Output should contain at least one device
    [[ -n "$output" ]] || fail "No devices listed"
    
    # Should show YubiKey with serial
    assert_output_contains "YubiKey.*Serial:"
}

@test "Device: Display PIV application info" {
    show_test_section "Testing PIV status display"
    
    # Ensure we start from factory state for predictable output
    reset_piv_to_factory
    
    run piv_tool info
    assert_success
    
    # Should show version information
    assert_output_contains "PIV version"
    
    assert_output_contains "PIN tries remaining: 3/3"
    
    assert_output_contains "WARNING! Using default PUK"
    
    assert_output_contains "WARNING! Using default Management key"
    
    # Should have basic structure without errors
    [[ ! "$output" =~ "Error\|Failed" ]] || fail "Info command reported errors"
}

@test "Device: Reset PIV to factory defaults" {
    show_test_section "Testing PIV factory reset"
    
    # Change PIN first
    run piv_tool access change-pin --pin "$DEFAULT_PIN" --new-pin "$TEST_PIN"
    assert_success
    
    # Verify PIN was changed (info should show 3/3 retries but PIN should be changed)
    run piv_tool info
    assert_success
    
    # Reset PIV
    run piv_tool reset
    assert_success
    
    # Verify reset worked - should be able to use default PIN again
    run piv_tool access change-pin --pin "$DEFAULT_PIN" --new-pin "$TEST_PIN"
    assert_success
    
    # Reset back to factory for cleanup
    run piv_tool reset
    assert_success
    
    run piv_tool info
    assert_success
    assert_output_contains "WARNING! Using default PUK"
    assert_output_contains "WARNING! Using default Management key"
}