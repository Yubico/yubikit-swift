# ``YubiKit/Management/Session``

Session for YubiKey device management and configuration.

## Overview

Management.Session provides access to device-level operations like reading device information,
configuring enabled applications, and performing factory reset.

```swift
let connection = try await USBSmartCardConnection()
let session: Management.Session = try await .makeSession(connection: connection)

// Get device information
let info = try await session.getDeviceInfo()
print("Serial: \(info.serialNumber)")
print("Firmware: \(info.version)")
print("Form factor: \(info.formFactor)")

// Check supported capabilities
print("USB capabilities: \(info.supportedCapabilities[.usb] ?? 0)")
```

## Topics

### Session Operations

- ``getDeviceInfo()``
- ``updateDeviceConfig(_:reboot:lockCode:newLockCode:)``
- ``resetDevice()``
- ``supports(_:)``

### Types

- ``Management/Feature``

### Errors

- ``ManagementSessionError``
