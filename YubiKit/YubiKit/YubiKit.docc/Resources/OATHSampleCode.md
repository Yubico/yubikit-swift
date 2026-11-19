# OATHSample: Basic OATH app showcasing how to integrate the SDK

This sample shows how to build an iOS and macOS app that reads TOTP codes from YubiKeys. The app demonstrates establishing connections, managing connection lifecycle, using ``OATHSession`` to retrieve authentication codes and the firmware version.

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

The view owns a `Model` and awaits its wired monitor in a SwiftUI task. The monitor reads each connection, waits for it to close, and clears the display before waiting for another key. This excerpt shows how the monitor closes an established connection when its task is cancelled:

```swift
await withTaskCancellationHandler {
    await update(using: connection)
    let closeError = await connection.waitUntilClosed()
    clear()
    if !Task.isCancelled, let closeError {
        error = closeError
    }
} onCancel: {
    // Cancellation alone does not end waitUntilClosed().
    Task { await connection.close(error: nil) }
}
```

The monitor also closes a connection that arrives after cancellation. It waits before retrying discovery errors and pauses discovery during NFC scans. The app uses one macOS window and disables multiple iOS scenes to avoid competing wired monitors.

### NFC Connections

The scan button and pull-to-refresh call `scanNFC()`. The model prevents overlapping scans. The view disables NFC controls while a wired connection is open. Once connected, it reads the codes and closes the short-lived NFC connection:

```swift
await withTaskCancellationHandler {
    let succeeded = await update(using: connection)
    if succeeded {
        await connection.close(message: "Codes calculated")
    } else {
        await connection.close(error: error)
    }
} onCancel: {
    Task { await connection.close(error: nil) }
}
```

The model filters user cancellation and task cancellation. A failed read clears the previous results and closes without the success message. Successful NFC results remain visible after the connection closes.

## Working with YubiKey Data

### Reading OATH Codes

The model reads codes and publishes a complete result only if the task is still active:

```swift
@discardableResult
func update(using connection: SmartCardConnection) async -> Bool {
    do {
        try Task.checkCancellation()
        let session = try await OATHSession.makeSession(connection: connection)
        let result = try await session.calculateCredentialCodes()
        let version = await session.version.description
        try Task.checkCancellation()
        accounts = result.map { credential, code in
            Account(id: credential.id, label: credential.label, code: code?.code, issuer: credential.issuer)
        }
        keyVersion = version
        readError = nil
        connectionType = connection.connectionType
        error = nil
        return true
    } catch {
        guard !Task.isCancelled else { return false }
        clear()
        readError = error
        self.error = error
        return false
    }
}
```

`calculateCredentialCodes()` returns an array of credential and optional-code pairs. HOTP credentials and credentials that require touch have no code in this result. A locked OATH application produces an error because this sample does not unlock it. Each account uses the credential ID for stable row identity.

### Getting Device Information

The firmware version is available from the same OATH session:

```swift
let version = await session.version.description
```

Reading codes does not require selecting the Management application.

## SwiftUI Integration

### Reacting to Connection Changes

The view owns the model with `@StateObject`. Its task keeps the wired monitor within the view's lifetime:

```swift
.task { await model.monitorWiredConnections() }
```

The model publishes accounts, firmware version, connection type, and errors. The Settings sheet observes the same model with `@ObservedObject`.

### Platform-Specific Features

The app handles iOS vs macOS differences with conditional compilation:

```swift
#if os(iOS)
if model.hasWiredConnection {
    accountsList
} else {
    accountsList.refreshable { await model.scanNFC() }
}
#else
accountsList
#endif
```

iOS users can pull-to-refresh to scan with NFC when no wired connection is open. macOS uses USB connections.

### Connection Type Detection

The sample includes a useful extension to identify connection types:

```swift
extension SmartCardConnection {
    var connectionType: String {
        switch self {
        #if os(iOS)
        case _ as NFCSmartCardConnection: return "NFC"
        case _ as LightningSmartCardConnection: return "Lightning"
        #endif
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

When you unplug your YubiKey, the app doesn't crash or freeze - it detects the disconnection via `waitUntilClosed()` and immediately starts waiting for the next YubiKey. This creates a smoother user experience where the app responds when you plug / unplug a YubiKey.

NFC works differently since you can't continuously scan - the user has to explicitly initiate each scan. That's why NFC connections are handled separately through user actions like the scan button or pull-to-refresh.

### Error handling for hardware connections

Hardware connections are unreliable by nature. Users will unplug devices mid-operation, walk away during NFC scans, or have connectivity issues. The sample handles this gracefully:

- Connection failures are caught and stored as errors
- User cancellations (like dismissing NFC scan) are filtered out to avoid unnecessary error alerts
- Session errors are handled similarly - show the error but maintain app functionality

### Working with Swift actors

YubiKit sessions are Swift actors that handle their own threading. The sample shows how to integrate this with SwiftUI's main actor requirements:

- `Model` runs on `@MainActor` so it can directly update `@Published` properties
- Session calls happen on the session's actor, then results are passed back to update the UI
- Everything uses `async/await`
