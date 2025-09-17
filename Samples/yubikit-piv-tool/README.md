# PIVTool

Command-line tool demonstrating PIV functionality with YubiKit.

[![Demo: YubiKit PIV Tool](https://asciinema.org/a/JeMHOazHlGMUYtzNP3zCRy7XA.svg)](https://asciinema.org/a/JeMHOazHlGMUYtzNP3zCRy7XA)

## Overview

This sample tool shows how to:
- Generate keys directly on the YubiKey
- Manage certificates and perform digital signatures
- Handle PIN/PUK authentication and management keys
- Work with different key types (RSA, ECDSA, Ed25519, X25519)

## Documentation

For a detailed walkthrough of this sample, see the [PIVTool documentation](https://yubico.github.io/yubikit-swift/documentation/yubikit/pivtoolsamplecode).

## Build and Run

```bash
make
```

## Test

```bash
make test
```

Tests require:
- YubiKey connected via USB
- BATS test framework (`brew install bats-core`)