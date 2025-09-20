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
import Testing

@testable import YubiKit

extension Logger {
    private static var subsystem = "com.yubico.YubiKit.Test"
    static let test = Logger(subsystem: subsystem, category: "Test")
}

protocol HasTestLogger: HasLogger {}

extension HasTestLogger {
    public static var logger: Logger { .test }
}

@inline(__always)
public func reportSkip(reason: String, function: String = #function) {
    // `severity` argument is arriving in Swift 6.3
    Issue.record(" Test \(function)() skipped: \"\(reason)\"" /*, severity: .warning */)
}

@inline(__always)
public func trace(_ message: String) {
    Logger.test.trace("\(message)")
}
