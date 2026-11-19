# OATHSample

SwiftUI authenticator app demonstrating OATH/TOTP functionality with YubiKit.

## Overview

This sample app shows how to:
- Connect to YubiKeys via NFC, USB-C, and Lightning
- Read TOTP codes and list HOTP or touch-required accounts
- Handle connection lifecycle in a reactive UI
- Display device information

## Documentation

For a detailed walkthrough of this sample, see the [OATHSample documentation](https://yubico.github.io/yubikit-swift/documentation/yubikit/oathsamplecode).

## Build and Run

Open `OATHSample.xcodeproj` in Xcode and run on a physical device (for NFC support) or macOS.

## Model tests

Run `swift test --package-path Samples/OATHSample` from the repository root.
These tests use a fake smart-card connection and do not access a YubiKey.
