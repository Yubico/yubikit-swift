# ``YubiKit/WiredSmartCardConnection``

Convenience factory for connecting to a YubiKey via USB or Lightning.

## Overview

WiredSmartCardConnection automatically detects the appropriate wired connection type
for the current device. On iOS devices with a Lightning port, it connects via Lightning.
On iOS devices with USB-C or macOS, it connects via USB SmartCard.

```swift
// Connect to any wired YubiKey (USB or Lightning)
let connection = try await WiredSmartCardConnection.makeConnection()
let session = try await OATHSession.makeSession(connection: connection)
```

This is useful when you want to support both USB and Lightning YubiKeys without
writing platform-specific code.

> Note: For NFC connections, use ``NFCSmartCardConnection`` directly.

## Topics

### Creating a Connection

- ``makeConnection()``
