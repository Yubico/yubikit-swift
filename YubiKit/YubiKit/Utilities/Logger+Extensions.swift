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

import OSLog

// MARK: - Generic Protocol
protocol HasLogger {
    static var logger: Logger { get }
}

extension HasLogger {
    var logger: Logger { Self.logger }
}

// MARK: - Specific Protocols
protocol HasSmartCardLogger: HasLogger {}
extension HasSmartCardLogger {
    static var logger: Logger { .smartCard }
}

protocol HasSecurityDomainLogger: HasLogger {}
extension HasSecurityDomainLogger {
    static var logger: Logger { .securityDomain }
}

protocol HasSCPLogger: HasLogger {}
extension HasSCPLogger {
    static var logger: Logger { .scp }
}

extension Logger {
    private static let subsystem = "com.yubico.YubiKit"

    static let system = Logger(subsystem: subsystem, category: "System")
    static let connection = Logger(subsystem: subsystem, category: "Connection")

    static let nfc = Logger(subsystem: subsystem, category: "NFC")
    static let lightning = Logger(subsystem: subsystem, category: "Lightning")
    static let smartCard = Logger(subsystem: subsystem, category: "SmartCard")

    static let oath = Logger(subsystem: subsystem, category: "OATH")
    static let management = Logger(subsystem: subsystem, category: "Management")
    static let piv = Logger(subsystem: subsystem, category: "PIV")
    fileprivate static let securityDomain = Logger(subsystem: subsystem, category: "SecurityDomain")

    fileprivate static let scp = Logger(subsystem: subsystem, category: "SCP")

    nonisolated static func export() async throws -> String {
        Logger.system.info("Logger, export(): compiling logs.")
        let store = try OSLogStore(scope: .currentProcessIdentifier)
        let date = Date.now.addingTimeInterval(-48 * 3600)
        let position = store.position(date: date)
        let predicate = NSPredicate(format: "subsystem == \"\(subsystem)\"")
        let entries =
            try store
            .getEntries(at: position, matching: predicate)
            .compactMap { $0 as? OSLogEntryLog }
            .filter { $0.subsystem == subsystem }
            .map { "\($0.date.formatted(date: .omitted, time: .standard)) [\($0.category)] \($0.composedMessage)" }
            .reduce(into: "", { $0 += "\n\($1)" })
        return entries
    }
}

// MARK: - RAII style scope tracer
// Will be wrapped in a '@TraceScope' macro when Swift 6 is available
/*
class _Trace {
    let name: String
    let logger: Logger

    init(_ name: String, logger: Logger) {
        self.name = name
        self.logger = logger
        logger.trace(">>> \(name, privacy: .public)")
    }

    deinit {
        logger.trace("<<< \(self.name, privacy: .public)")
    }
}

*/
// MARK: - These functions trace with a message
extension HasLogger {
    // static helper
    @inline(__always)
    static func trace(
        _ function: String = #function,
        logger: Logger = logger,
        message: String
    ) {

        let typeName = String(describing: type(of: self))
        let label = "\(typeName).\(function)"

        logger.trace("\(label): \(message)")
    }

    // instance helper
    @inline(__always)
    func trace(
        _ function: String = #function,
        logger: Logger = logger,
        message: String
    ) {

        let typeName = String(describing: type(of: self))
        var label = "\(typeName).\(function)"

        if let obj = self as AnyObject? {
            let ptr = Unmanaged.passUnretained(obj).toOpaque()
            let ptrStr = String(format: "0x%08x", UInt(bitPattern: ptr) & 0xFFFF_FFFF)
            label = "\(typeName)[\(ptrStr)].\(function)"
        }

        logger.trace("\(label): \(message)")
    }
}
