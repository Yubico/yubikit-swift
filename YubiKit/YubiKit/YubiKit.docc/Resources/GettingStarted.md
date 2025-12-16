# Getting Started

Prepare your project to connect to the YubiKey via NFC, SmartCard and Lightning.

## Overview

The YubiKit framework is distributed using the Swift Package Manager. To add the framework to your project follow these steps:

1. Select your project.

2. Choose the "Package Dependencies" tab.

3. Press the plus-button to bring up the add package dialog.

![An image showing how to add the YubiKit SDK to your Xcode project.](add-framework-1.png)

4. Enter `https://github.com/Yubico/yubikit-swift/` in the search field and select the Yubico Swift Package.

5. Press the "Add Package" button to add the SDK to your project.

![An image showing how to add the YubiKit SDK to your Xcode project.](add-framework-2.png)


### NFC

If you want your app to communicate with YubiKeys via NFC you need to add the wireless entitlement, list of NFC
application identifiers and a NFC Privacy statement to the application.

**Add Wireless entitlement**

1. Select your project.

2. Select your application target.

3. Choose the "Signing & Capabilities" tab.

4. Click the "+"-button to add a new capability.

5. Select the "Near Field Communication Tag" capability.

![An image showing how to add wireless entitlements to project.](nfc-entitlement.png)

**Add list of NFC application identifiers**

6. Choose the "Info" tab.

7. Add the "ISO7816 application identifiers for NFC" key to the "Custom iOS Target Properties".

![An image showing how to add the nfc application identifiers.](nfc-identifiers.png)

8. Add the Yubico NFC application identifiers to enable communication with the different
applications on the YubiKey.

```
A000000527471117  // YubiKey Management Application
A0000006472F0001  // FIDO/U2F
A0000005272101    // OATH
A000000308        // PIV
A000000527200101  // YubiKey application/OTP (for HMAC SHA1 challenge-response)
A000000151000000  // Security Domain
```

![An image showing the list of nfc identifiers added.](nfc-identifiers-list.png)

**Add a NFC Privacy description**

9. Add the "Privacy - NFC Usage Scan Description" key and a string that describes what you will use NFC for in
the application e.g "The application needs access to NFC reading to communicate with your YubiKey."

![An image showing how to add NFC privacy string tro project.](nfc-privacy.png)

### SmartCard/USB

To support YubiKeys connected via the USB port on a device running iOS 16 or higher, you need to add the 
`com.apple.security.smartcard` entitlement to your application.

1. Select the application entitlements file.

2. Add the `com.apple.security.smartcard` entitlement to the entitlement list.

![An image showing how to add NFC privacy string to project.](smart-card.png)

> Note: The SmartCard/USB connection only support the CCID based applications on the YubiKey and does not support U2F, FIDO2 or OTP.

### Lightning/AccessoryConnection i.e 5Ci YubiKey

To add support for the 5Ci YubiKey that connect to the iPhone via the Lightning port you need to add the `com.yubico.ylp` string to the list of External Accessories.

1. Select your project.

2. Select your application target.

3. Choose the "Info" tab.

4. If not present add the `Supported external accessory protocols` key and insert the string `com.yubico.ylp` in its list.

![An image showing how to support for lightning YubiKeys.](external-accessory.png)

> Note: The YubiKey 5Ci is an Apple MFi certified external accessory and communicates over iAP2. Setting the value for `Supported external accessory protocols` to `com.yubico.ylp` will tell the app that all communication with the 5Ci YubiKey via the Lightning port is done using the External Accessory framework.

## Making Your First Connection

Now that your project is configured, you can start connecting to YubiKeys. YubiKit provides different connection types depending on how the YubiKey is connected to the device.

### Understanding Connection Types

YubiKit handles three different connection methods:

- **NFC**: Short-range wireless communication (iOS only)
- **USB**: Direct USB connection via SmartCard interface
- **Lightning**: YubiKey 5Ci connected to Lightning port (iOS only)

Each connection type works differently, so let's explore how to use them.

### NFC Connections

NFC connections are user-initiated and short-lived. The user must bring their YubiKey close to their device:

```swift
import YubiKit

// Start an NFC scan
do {
    let connection = try await NFCSmartCardConnection.makeConnection()

    // Use the connection quickly - NFC sessions have a timeout
    let session = try await OATHSession.makeSession(connection: connection)
    let codes = try await session.calculateCredentialCodes()

    // Always close NFC connections with a user message
    await connection.close(message: "OATH codes retrieved")

} catch {
    // Handle connection errors (user cancelled, no YubiKey found, etc.)
    print("NFC connection failed: \(error)")
}
```

NFC connections automatically show the iOS NFC interface and require user interaction to complete.

### USB and Lightning Connections

Wired connections are persistent - they stay connected until the YubiKey is unplugged:

```swift
import YubiKit

// Connect to any wired YubiKey (USB or Lightning)
do {
    let connection = try await WiredSmartCardConnection.makeConnection()

    // Perform operations - connection stays active
    let session = try await OATHSession.makeSession(connection: connection)
    let codes = try await session.calculateCredentialCodes()

    // Monitor for disconnection or close when done
    let error = await connection.waitUntilClosed()
    if let error = error {
        print("Connection closed with error: \(error)")
    }

} catch {
    print("Wired connection failed: \(error)")
}
```

The `WiredSmartCardConnection.makeConnection()` method automatically detects whether you're using USB or Lightning.

### Specific Connection Types

For more control, you can connect to specific interfaces:

```swift
// USB only
let usbConnection = try await USBSmartCardConnection.makeConnection()

// Lightning only (iOS)
let lightningConnection = try await LightningSmartCardConnection.makeConnection()

// NFC with custom message (iOS)
let nfcConnection = try await NFCSmartCardConnection.makeConnection(
    alertMessage: "Hold your YubiKey near the phone"
)
```

## Understanding Connection Lifecycle

**Critical:** Connections must be explicitly closed. You can only have one active connection to a YubiKey at any time.

### Connection Behavior

- **Exclusive access**: Only one connection can exist per YubiKey at any time
- **Manual closure required**: Dropping a connection reference does NOT automatically close it - you must call `close()`
- **Resource blocking**: An unclosed connection prevents new connections (throws `SmartCardConnectionError.busy`)

Connections are value types that act as exclusive access tokens to the underlying hardware resource.

## Working with Sessions

Once you have a connection, create sessions to access different YubiKey applications:

### OATH Session (TOTP/HOTP codes)

```swift
let session = try await OATHSession.makeSession(connection: connection)
let codes = try await session.calculateCredentialCodes()

for (credential, code) in codes {
    print("\(credential.label): \(code?.code ?? "Touch required")")
}
```

### PIV Session (Certificates and keys)

```swift
let session = try await PIVSession.makeSession(connection: connection)
let certificate = try await session.getCertificate(in: .authentication)
print("Found certificate: \(certificate.subject)")
```

### Management Session (Device information)

```swift
let session: Management.Session = try await .makeSession(connection: connection)
print("YubiKey version: \(await session.version)")

let deviceInfo = try await session.getDeviceInfo()
print("Device info: \(deviceInfo)")
```

## Connection Management Patterns

### For UI Applications

In SwiftUI or UIKit apps, you typically want to maintain persistent connections and react to connection changes. See <doc:OATHSampleCode> for complete examples of reactive connection management patterns that automatically update your UI when YubiKeys are plugged in or removed.

### For Command-Line Tools

CLI applications often use a simpler approach with a single connection per operation. See <doc:PIVToolSampleCode> for examples of how command-line tools handle connections for one-time operations.

## Next Steps

Now you're ready to build YubiKey applications! Check out the sample projects to see complete implementations:

- **OATHSample**: Shows how to build a TOTP authenticator app with SwiftUI
- **PIVTool**: Demonstrates PIV operations for certificates and digital signatures

### Build SDK documentation

You can also build the complete SDK documentation by selecting "Product" -> "Build Documentation" in Xcode. This gives you access to the full YubiKit API reference.

> Note: Select an iOS target when building documentation to include all connection types.
