#!/usr/bin/env bash

# OpenSSL validation helpers for PIV tool testing

validate_public_key_pem() {
    local pem_file="$1"
    [[ -f "$pem_file" ]] || return 1
    openssl pkey -pubin -in "$pem_file" -noout 2>/dev/null
}

validate_certificate_pem() {
    local cert_file="$1"
    [[ -f "$cert_file" ]] || return 1
    openssl x509 -in "$cert_file" -noout 2>/dev/null
}

validate_csr_pem() {
    local csr_file="$1"
    [[ -f "$csr_file" ]] || return 1
    openssl req -in "$csr_file" -noout 2>/dev/null
}

# Extract and validate certificate subject
get_certificate_subject() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject= *//'
}

# Extract public key algorithm from certificate
get_certificate_algorithm() {
    local cert_file="$1"
    openssl x509 -in "$cert_file" -noout -text 2>/dev/null | \
        grep "Public Key Algorithm" | \
        sed 's/.*Public Key Algorithm: *//'
}

# Extract public key algorithm from public key file
get_public_key_algorithm() {
    local key_file="$1"
    local output
    output=$(openssl pkey -pubin -in "$key_file" -noout -text 2>/dev/null | head -10)
    
    if [[ "$output" =~ "Modulus:" ]]; then
        # RSA keys show "Public-Key: (2048 bit)" followed by "Modulus:"
        echo "RSA"
    elif [[ "$output" =~ "pub:" ]]; then
        # ECC keys show "Public-Key: (256 bit)" followed by "pub:" 
        echo "EC"
    else
        echo "unknown"
    fi
}

# Verify that a certificate matches a public key
verify_certificate_key_match() {
    local cert_file="$1"
    local key_file="$2"
    
    # Extract public keys and compare
    local cert_pubkey_hash key_pubkey_hash
    cert_pubkey_hash=$(openssl x509 -in "$cert_file" -noout -pubkey 2>/dev/null | \
                      openssl pkey -pubin -outform DER 2>/dev/null | \
                      openssl dgst -sha256 2>/dev/null)
    
    key_pubkey_hash=$(openssl pkey -pubin -in "$key_file" -outform DER 2>/dev/null | \
                     openssl dgst -sha256 2>/dev/null)
    
    [[ "$cert_pubkey_hash" == "$key_pubkey_hash" ]]
}

get_key_size() {
    local key_file="$1"
    local output
    output=$(openssl pkey -pubin -in "$key_file" -noout -text 2>/dev/null | head -3)
    
    # RSA shows "RSA Public-Key: (2048 bit)"
    # ECC shows "Public-Key: (256 bit)"
    if [[ "$output" =~ ([0-9]+)\ bit ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo "unknown"
    fi
}


# Simple helper to check if OpenSSL is available
check_openssl_available() {
    command -v openssl >/dev/null 2>&1 || {
        skip "OpenSSL not available - required for cryptographic validation"
    }
}