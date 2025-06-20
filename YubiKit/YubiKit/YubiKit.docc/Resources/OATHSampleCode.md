# OATHSample: Basic OATH app showcasing how to integrate the SDK

This sample project shows how to integrate the SDK into an iOS and MacOS app. It lists OATH codes 
using the ``OATHSession`` and has a separate view that displays the version number of the key. The version
number is retrieved using the ``ManagementSession``.

@Metadata {
    @CallToAction(
        purpose: link,
        url: "https://github.com/Yubico/yubikit-swift/tree/main/Samples/OATHSample")
    @PageKind(sampleCode)
    @PageColor(green)
}

The sample project consist of two views. One that list the OATH codes calculated, either using USB-C, Lightning or NFC.
The other view simply displays the version number of the YubiKey. This view also supports all three connection types.

> Note: This is only a sample project and there is currently no handling for password protected YubiKeys.

## OATH view

The main function of the OATH part of the app is the `startWiredConnection()` function. This will cancel any previous
`wiredConnectionTask` and create a new one. In the Task it will use the ``Connections`` helper to start waiting for
a wired connection. Depending on the device this will either be a ``LightningConnection`` or a ``SmartCardConnection``.
Once a connection has been established we check that the task hasn't been cancelled before proceeding.
The `calculateCodes(connection:)` function creates a new ``OATHSession`` and
calls `.calculateCodes()` on the session. The result is then used to populate the list of codes in the UI.

At this point the app will wait for the connection to close. This can be caused by the user unplugging the YubiKey or
a connection error of some sort forcing the connection to close. If the connection is closed the app will clean up
the user interface and loop around `startWiredConnection()` again.
```swift
func startWiredConnection() {
    wiredConnectionTask?.cancel()
    wiredConnectionTask = Task { @MainActor in
        while true {
            do {
                error = nil
                guard !Task.isCancelled else { return }
                // Wait for a suitable wired connection for the current device.
                let connection = try await WiredConnection.connection()
                guard !Task.isCancelled else { return }
                try await calculateCodes(connection: connection)
                // Wait for the connection to close, i.e the YubiKey to be unplugged from the device.
                // If the YubiKey was simply unplugged it will return nil, otherwise the error
                // causing the disconnect will be returned.
                guard !Task.isCancelled else { return }
                error = await connection.connectionDidClose()
                accounts.removeAll()
                source = "no connection"
                continue
            } catch (let e) {
                error = e
                continue
            }
        }
    }
}

@MainActor private func calculateCodes(connection: Connection) async throws {
    self.error = nil
    let session = try await OATHSession.session(withConnection: connection)
    let result = try await session.calculateCodes()
    self.accounts = result.map { Account(label: $0.0.label, code: $0.1?.code ?? "****") }
    self.source = connection.connectionType
}
```

## Settings view

To bring up the settings view we've added a `Button` to the `OATHListView`. The button will stop
any wired connections and cancel the wait for new connections. It will then present the `SettingsView`
as a SwiftUI sheet.

The `SettingsModel` is simpler since it will only retrieve the version number once when it appears
and it does not handle YubiKeys being unplugged and plugged back again. In this case we can use the
`Connection.anyConnection()` function that will return any wired YubiKey that might be connected
or, if no wired key is present it will start scanning for a NFC key. Once connected we create 
the ``ManagementSession`` and get the key version.
```swift
func getKeyVersion() {
    Task { @MainActor in
        self.error = nil
        do {
            let connection = try await AnyConnection.connection()
            let session = try await ManagementSession.session(withConnection: connection)
            self.keyVersion = session.version.description
            #if os(iOS)
            if let nfcConnection = connection.nfcConnection {
                self.connection = "NFC"
                await nfcConnection.close(message: "YubiKey version read")
            } else {
                self.connection = connection as? SmartCardConnection != nil ? "SmartCard" : "Lightning"
            }
            #else
            self.connection = "SmartCard"
            #endif
        } catch {
            self.error = error
        }
    }
}
```
