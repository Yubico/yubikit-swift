# YubiKit PIV Tool

Command-line PIV management tool built with YubiKit Swift SDK. Based on `ykman piv` functionality.

[![Demo: YubiKit PIV Tool](https://asciinema.org/a/JeMHOazHlGMUYtzNP3zCRy7XA.svg)](https://asciinema.org/a/JeMHOazHlGMUYtzNP3zCRy7XA)

## Build

```bash
make
```

## Test

```bash
make test
```

Requires physical YubiKey connected via USB-C.

## Requirements
- YubiKey
- BATS for testing (`brew install bats-core`)