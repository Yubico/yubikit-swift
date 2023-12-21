#  Yubico Swift SDK - YubiKit

**Connect and run commands on the different applications on a YubiKey. The framework support connecting using NFC, Lightning and USB-C.**

**🚨 Note: This is a prerelease and is not intended for use in a production app. 🚨**

The YubiKit Swift SDK provides a modern async/await version of the YubiKit framework, making it easy to integrate
in Swift and SwiftUI based applications. The async/await syntax provides an easy to read and powerful way of
creating connections and sending commands to the different applications on the YubiKey.

```swift
let connection = try await NFCConnection.connection()
let session = try await OATHSession.session(withConnection: connection)
let codes = try await session.calculateCodes()
```

The SDK runs on iOS from version 16.0 and up. On macOS it requires version 13.0 or higher. On iOS connecting 
using NFC, Lightning and USB-C is supported and on macOS USB-C.

There's also a set of wrappers providing delegate and callback based versions of the SDK, simplifiying
transitioning from the old Objective-C SDK.

[Getting started](https://crispy-adventure-222z492.pages.github.io/documentation/yubikit/gettingstarted)

[Full documentation](https://crispy-adventure-222z492.pages.github.io/documentation/yubikit)
