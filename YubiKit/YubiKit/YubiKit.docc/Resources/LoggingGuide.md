# Logging

Choose YubiKit's log level and backend with ``Logging/configure(logLevel:factory:)``.

## Overview

No setup is required. YubiKit defaults to `debug` on stdout when compiled with `DEBUG`,
or `info` on stderr otherwise. You can override either default:

```swift
import YubiKit
import Logging

// Show warnings and errors.
Logging.configure(logLevel: .warning)

// Use your preferred backend.
Logging.configure(logLevel: .debug) { label in
    StreamLogHandler.standardOutput(label: label)
}

// Turn logging off.
Logging.configure { _ in SwiftLogNoOpLogHandler() }

// Restore defaults.
Logging.configure()
```

Add [SwiftLog](https://github.com/apple/swift-log)'s `Logging` product to your app target
to use its backend types. Any SwiftLog `LogHandler` can be supplied by the factory.

Each call replaces both settings. Omitting the factory restores YubiKit's backend;
omitting the level uses the selected handler's level. Changes apply to existing sessions,
though logs already in progress may use the previous settings.

YubiKit's configuration does not affect other libraries. To share your app's backend,
pass its factory explicitly; global `LoggingSystem.bootstrap` does not select YubiKit's backend.
Factories may run concurrently and must not log through YubiKit themselves.

### Traffic logging

```swift
Logging.configure(logLevel: .trace)
```

Raw traffic and SCP plaintext logs require **YubiKit to be compiled with `DEBUG`**.
Neither configuration nor a custom backend can enable them in other builds.
Custom connections are responsible for their own traffic logging.

> Warning: Debug logs can include account names and credential identifiers.
> Trace logs can include PINs, credentials, and cryptographic keys. Protect or redact logs before sharing them.

### Custom backends

Labels identify categories, such as `com.yubico.YubiKit.OATH` or `com.yubico.YubiKit.FIDO`.
Metadata carries details such as byte counts and error codes; the default backend displays
these as `key=value` pairs. Message wording and metadata keys are not a stable API.

Your backend controls formatting, storage, and export. YubiKit does not retain log messages.
