# WebAuthnInterceptorSample

Sample app demonstrating FIDO2/WebAuthn functionality by intercepting browser credentials API in a WKWebView and routing requests to a YubiKey.

## Overview

This sample app shows how to:
- Intercept `navigator.credentials.create()` and `navigator.credentials.get()` in a WKWebView
- Route WebAuthn requests to YubiKey via NFC (iOS) or USB HID (macOS)
- Handle PIN entry and verification
- Support PRF extension (hmac-secret) for deriving secrets from credentials

## Documentation

For a detailed walkthrough of this sample, see the [WebAuthnInterceptorSample documentation](https://yubico.github.io/yubikit-swift/documentation/yubikit/webauthninterceptorsamplecode).

## Build and Run

Open `WebAuthnInterceptorSample.xcodeproj` in Xcode and run on a physical device (iOS) or macOS.

## Usage

1. Navigate to a WebAuthn-enabled site (defaults to demo.yubico.com)
2. Register or authenticate with your YubiKey
3. Enter PIN when prompted
4. Tap (NFC) or insert (USB) your YubiKey
