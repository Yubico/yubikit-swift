# PIVTool

Command-line tool demonstrating PIV functionality with YubiKit.

[![Demo: YubiKit PIV Tool](https://asciinema.org/a/JeMHOazHlGMUYtzNP3zCRy7XA.svg)](https://asciinema.org/a/JeMHOazHlGMUYtzNP3zCRy7XA)

## Overview

This sample tool shows how to:
- Generate keys directly on the YubiKey
- Manage certificates and perform digital signatures
- Handle PIN/PUK authentication and management keys
- Work with different key types (RSA, ECDSA, Ed25519, X25519)

ML-DSA and ML-KEM require YubiKey firmware 6.0 or later.

## Documentation

For a detailed walkthrough of this sample, see the [PIVTool documentation](https://yubico.github.io/yubikit-swift/documentation/yubikit/pivtoolsamplecode).

## Build and Run

```bash
make
```

## Test

Run `swift test` for unit tests.

For hardware tests, install Bats (`brew install bats-core`) and connect a dedicated test YubiKey over USB. The tests reset PIV.

```bash
PIV_TOOL_DESTRUCTIVE_TESTS=1 make test
```
