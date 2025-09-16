# OATHSample: Basic OATH app showcasing how to integrate the SDK

This sample shows how to build an iOS and macOS app that reads TOTP codes from YubiKeys. The app demonstrates establishing connections, managing connection lifecycle, using ``OATHSession`` to retrieve authentication codes, and ``ManagementSession`` to get device information.

@Metadata {
    @CallToAction(
        purpose: link,
        url: "https://github.com/Yubico/yubikit-swift/tree/main/Samples/OATHSample")
    @PageKind(sampleCode)
    @PageColor(green)
}

The sample creates an authenticator app that:
- Establishes connections to YubiKeys via USB, Lightning, or NFC
- Manages connection lifecycle (detecting plugged/unplugged devices)
- Lists TOTP codes stored on the YubiKey
- Shows device information like firmware version
- Handles connection errors and user cancellations gracefully

This sample focuses on read-only operations and doesn't handle password-protected YubiKeys or credential management.

## Connection Management

### Handling Wired Connections

The app uses a `ConnectionManager` to handle persistent connections to plugged-in YubiKeys. This approach ensures your app stays responsive when users plug and unplug their YubiKeys:

```swift
private func startWiredConnection() {
    wiredConnectionTask = Task { @MainActor in
        while !Task.isCancelled {
            do {
                let newConnection = try await WiredSmartCardConnection.connection()
                wiredConnection = newConnection

                // Wait for disconnection
                let closeError = await newConnection.connectionDidClose()
                wiredConnection = nil
            } catch {
                self.error = error
            }
        }
    }
}
```

The key insight here is using `connectionDidClose()` to detect when the YubiKey is unplugged, then automatically waiting for the next connection.

### NFC Connections

NFC connections work differently - they're initiated by user action and are short-lived:

```swift
func requestNFCConnection() async {
    do {
        nfcConnection = try await NFCSmartCardConnection.connection()
    } catch {
        self.error = error
    }
}
```

When an NFC connection is established, the app fetches data and immediately closes it with a user message:

```swift
Task {
    await model.update(using: connection)
    await connection.close(message: "Codes calculated")
}
```

## Working with YubiKey Data

### Reading OATH Codes

Once you have a connection, getting TOTP codes is straightforward:

```swift
private func calculateCodes(using connection: SmartCardConnection) async {
    do {
        let session = try await OATHSession.session(withConnection: connection)
        let result = try await session.calculateCodes()

        accounts = result.map { credential, code in
            Account(
                label: credential.label,
                code: code?.code,
                issuer: credential.issuer,
                type: credential.type
            )
        }
    } catch {
        self.error = error
    }
}
```

The `calculateCodes()` method returns a dictionary mapping credentials to their current codes. Some codes might be `nil` if they require touch or are password-protected.

### Getting Device Information

Use `ManagementSession` to get YubiKey information:

```swift
private func getKeyVersion(using connection: SmartCardConnection) async {
    do {
        let session = try await ManagementSession.session(withConnection: connection)
        self.keyVersion = session.version.description
    } catch {
        self.error = error
    }
}
```

The `Model` class combines both operations in a single `update` method:

```swift
func update(using connection: SmartCardConnection) async {
    await calculateCodes(using: connection)
    await getKeyVersion(using: connection)
    connectionType = connection.connectionType
}
```

## SwiftUI Integration

### Reacting to Connection Changes

The app uses SwiftUI's `@Published` properties and `onReceive` to update the UI when connections change:

```swift
.onReceive(connectionManager.$wiredConnection) { newConnection in
    guard let connection = newConnection else {
        model.clear()  // Clear UI when YubiKey unplugged
        return
    }
    Task { await model.update(using: connection) }
}
```

This pattern ensures the UI immediately updates when YubiKeys are plugged in or removed.

### Platform-Specific Features

The app handles iOS vs macOS differences with conditional compilation:

```swift
#if os(iOS)
.refreshable {
    await connectionManager.requestNFCConnection()
}
#endif
```

iOS users can pull-to-refresh to scan with NFC, while macOS users only see USB options.

### Error Handling in SwiftUI

The sample shows how to handle different types of connection errors:

```swift
.onReceive(connectionManager.$error) { error in
    switch error {
    case .some(ConnectionError.cancelledByUser):
        return  // Don't show error for user cancellation
    default:
        model.error = error
    }
}
```

This prevents showing errors when users intentionally cancel NFC scans.

### Connection Type Detection

The sample includes a useful extension to identify connection types:

```swift
extension SmartCardConnection {
    var connectionType: String {
        switch self {
        case _ as NFCSmartCardConnection: return "NFC"
        case _ as LightningSmartCardConnection: return "Lightning"
        case _ as USBSmartCardConnection: return "USB"
        default: return "Unknown"
        }
    }
}
```

This is helpful because NFC connections are slower than USB, and users like to know how their YubiKey is connected.

## Architecture Decisions

### Why the connection management works this way

The sample uses a background loop that continuously waits for wired connections. This might seem unusual, but it solves a key problem: YubiKeys get plugged and unplugged frequently, but apps need to stay responsive.

When you unplug your YubiKey, the app doesn't crash or freeze - it detects the disconnection via `connectionDidClose()` and immediately starts waiting for the next YubiKey. This creates a smoother user experience where the app responds when you plug / unplug a YubiKey.

NFC works differently since you can't continuously scan - the user has to explicitly initiate each scan. That's why NFC connections are handled separately through user actions like the scan button or pull-to-refresh.

### Error handling for hardware connections

Hardware connections are unreliable by nature. Users will unplug devices mid-operation, walk away during NFC scans, or have connectivity issues. The sample handles this gracefully:

- Connection failures are caught and stored as errors
- User cancellations (like dismissing NFC scan) are filtered out to avoid unnecessary error alerts
- Session errors are handled similarly - show the error but maintain app functionality

### Working with Swift actors

YubiKit sessions are Swift actors that handle their own threading. The sample shows how to integrate this with SwiftUI's main actor requirements:

- `ConnectionManager` runs on `@MainActor` so it can directly update `@Published` properties
- Session calls happen on the session's actor, then results are passed back to update the UI
- Everything uses `async/await`
