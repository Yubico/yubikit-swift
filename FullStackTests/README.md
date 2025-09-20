# FullStackTests

Integration tests for the YubiKit Swift SDK that require physical YubiKey hardware.

## Overview

This test suite validates YubiKit functionality against real YubiKey devices. Tests cover OATH, PIV, Management, SCP, Connection handling, and FIDO operations.

## Setup

Before running tests, add your YubiKey's serial number to the allowed list in `AllowedConnections.swift`:

```swift
let allowedSerialNumbers: [UInt] = [
    12345678,  // Add your YubiKey serial number here
]
```

## Running Tests

### Test Runner Script
```bash
./run-tests.sh
```

### Xcode
Open `FullStackTests.xcodeproj` and run tests normally (⌘U).