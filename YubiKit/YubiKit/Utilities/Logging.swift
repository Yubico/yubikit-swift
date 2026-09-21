// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation
import Logging

/// Configures logging for YubiKit connections and sessions.
///
/// Defaults to `debug` on stdout when YubiKit is compiled with `DEBUG`, or `info` on stderr otherwise.
/// Use ``configure(logLevel:factory:)`` to override the level or backend.
/// Raw traffic requires both `DEBUG` and explicit opt-in at `trace`.
///
/// > Warning: Debug messages can include account names and credential identifiers.
/// > Trace messages can include PINs and cryptographic keys. Protect captured logs before sharing them.
public enum Logging {
    /// Sets YubiKit's log level and backend.
    ///
    /// Each call replaces the previous configuration. Call `Logging.configure()` to restore defaults.
    ///
    /// - Parameters:
    ///   - logLevel: Minimum severity. Defaults to `.debug` when YubiKit is compiled with `DEBUG`,
    ///     or `.info` otherwise. A custom backend uses its own default level.
    ///     Raw traffic requires `.trace` and YubiKit compiled with `DEBUG`.
    ///   - factory: Creates a SwiftLog handler for each category label. If omitted, logs to the console.
    ///     May run concurrently; must not call YubiKit logging.
    public static func configure(
        logLevel: Logger.Level? = nil,
        factory: (@Sendable (String) -> any LogHandler)? = nil
    ) {
        storage.replace(logLevel: logLevel, factory: factory)
    }

    static func logger(category: String) -> Logger {
        storage.logger(label: "com.yubico.YubiKit.\(category)")
    }

    private static let storage = Storage()

    private final class Configuration: Sendable {
        let logLevel: Logger.Level?
        let factory: (@Sendable (String) -> any LogHandler)?

        init(logLevel: Logger.Level?, factory: (@Sendable (String) -> any LogHandler)?) {
            self.logLevel = logLevel
            self.factory = factory
        }
    }

    // The lock protects configuration and cached loggers. User code runs outside it.
    private final class Storage: @unchecked Sendable {
        func replace(logLevel: Logger.Level?, factory: (@Sendable (String) -> any LogHandler)?) {
            let replacement = Configuration(logLevel: logLevel, factory: factory)
            let previous = lock.withLock {
                let previous = (configuration, loggers)
                configuration = replacement
                loggers = [:]
                return previous
            }
            // Handler and factory deinitializers can call back into configuration.
            withExtendedLifetime(previous) {}
        }

        func logger(label: String) -> Logger {
            let snapshot = lock.withLock { (configuration, loggers[label]) }
            if let logger = snapshot.1 { return logger }

            var logger: Logger
            if let factory = snapshot.0.factory {
                logger = Logger(label: label, factory: factory)
            } else {
                logger = Logger(label: label) { label in
                    #if DEBUG
                    var handler = StreamLogHandler.standardOutput(label: label)
                    handler.logLevel = .debug
                    #else
                    var handler = StreamLogHandler.standardError(label: label)
                    handler.logLevel = .info
                    #endif
                    return handler
                }
            }
            if let level = snapshot.0.logLevel { logger.logLevel = level }

            return lock.withLock {
                guard configuration === snapshot.0 else { return logger }
                if let cached = loggers[label] { return cached }
                loggers[label] = logger
                return logger
            }
        }

        private let lock = NSLock()
        private var configuration = Configuration(logLevel: nil, factory: nil)
        private var loggers: [String: Logger] = [:]
    }
}
