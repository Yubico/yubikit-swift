#!/usr/bin/env bash
piv_tool() {
    ../bin/yubikit-piv-tool "$@"
}

check_yubikey_connected() {
    if ! piv_tool list >/dev/null 2>&1; then
        skip "No YubiKey detected - test requires physical hardware"
    fi
    
    local device_count
    device_count=$(piv_tool list 2>/dev/null | wc -l)
    if [[ $device_count -eq 0 ]]; then
        skip "No YubiKey detected - test requires physical hardware"
    elif [[ $device_count -gt 1 ]]; then
        skip "Multiple YubiKeys detected - please connect only one device"
    fi
}

reset_piv_to_factory() {
    echo -e "${YELLOW}Resetting PIV to factory state...${NC}" >&2
    run piv_tool reset
    if [[ $status -ne 0 ]]; then
        echo -e "${RED}Failed to reset PIV: $output${NC}" >&2
        return 1
    fi
    
    sleep 1
}

generate_test_key() {
    local slot="$1"
    local algorithm="$2" 
    local output_file="$3"
    
    run piv_tool keys generate "$slot" "$output_file" \
        --algorithm "$algorithm" \
        --pin-policy DEFAULT \
        --touch-policy DEFAULT \
        --pin "$DEFAULT_PIN" \
        --management-key "$DEFAULT_MGMT_KEY"
    
    [[ $status -eq 0 ]] || return 1
    [[ -f "$output_file" ]] || return 1
}

show_test_section() {
    local section="$1"
    echo -e "${GREEN}=== $section ===${NC}" >&2
}