# YubiKit Swift SDK

[![Swift 6.1](https://img.shields.io/badge/Swift-6.1-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2016%2B%20%7C%20macOS%2013%2B-blue.svg)](https://developer.apple.com)
[![SPM Compatible](https://img.shields.io/badge/SPM-compatible-brightgreen.svg)](https://swift.org/package-manager/)
[![Documentation](https://img.shields.io/badge/docs-DocC-blue.svg)](https://yubico.github.io/yubikit-swift/documentation/yubikit/)
[![License](https://img.shields.io/badge/License-Apache%202.0-lightgray.svg)](LICENSE)

Swift SDK for YubiKey integration on iOS and macOS.

## Overview

YubiKit provides a native Swift interface with async/await for YubiKey hardware devices.

```swift
let connection = try await NFCSmartCardConnection.makeConnection()
let session = try await OATHSession.makeSession(connection: connection)
let codes = try await session.calculateCodes()
await connection.close(message: "Done")
```

## About

YubiKit uses a layered architecture where the connection layer handles communication via NFC, Lightning, and USB-C, while application-specific sessions are built on top of these connections. All APIs use modern Swift async/await concurrency patterns for clean, readable code.

### Supported Applications

**OATH** - Configure and use TOTP/HOTP credentials for two-factor authentication

**PIV** - Smart card functionality including X.509 certificate management, key generation (RSA, ECDSA, Curve25519), and cryptographic operations

**Management** - Read YubiKey metadata (serial number, firmware version) and configure device settings

**Secure Channel Protocol** - SCP03 and SCP11 for encrypted communication

## Installation

### Swift Package Manager

```
https://github.com/Yubico/yubikit-swift
```

## Documentation

- [Getting Started Guide](https://yubico.github.io/yubikit-swift/documentation/yubikit/gettingstarted)
- [API Documentation](https://yubico.github.io/yubikit-swift/documentation/yubikit/)
- [Configuration Guide](https://yubico.github.io/yubikit-swift/documentation/yubikit/gettingstarted#preparing-your-project)

## Sample Apps

Learn by example:

- **[OATHSample](Samples/OATHSample)** - SwiftUI authenticator app
- **[PIVTool](Samples/yubikit-piv-tool)** - Command-line PIV operations

## Requirements

- iOS 16.0+ / macOS 13.0+

## Support

- [GitHub Issues](https://github.com/Yubico/yubikit-swift/issues)
- [Developer Documentation](https://developers.yubico.com)

## License

Apache License 2.0
