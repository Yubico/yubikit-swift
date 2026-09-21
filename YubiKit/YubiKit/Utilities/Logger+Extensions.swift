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

// MARK: - Generic Protocol
protocol HasLogger {
    static var logger: Logger { get }
}

extension HasLogger {
    var logger: Logger { Self.logger }
}

// MARK: - Specific Protocols
protocol HasOATHLogger: HasLogger {}
extension HasOATHLogger {
    static var logger: Logger { .oath }
}

protocol HasPIVLogger: HasLogger {}
extension HasPIVLogger {
    static var logger: Logger { .piv }
}

protocol HasManagementLogger: HasLogger {}
extension HasManagementLogger {
    static var logger: Logger { .management }
}

protocol HasSmartCardLogger: HasLogger {}
extension HasSmartCardLogger {
    static var logger: Logger { .smartCard }
}

protocol HasNFCLogger: HasLogger {}
extension HasNFCLogger {
    static var logger: Logger { .nfc }
}

protocol HasLightningLogger: HasLogger {}
extension HasLightningLogger {
    static var logger: Logger { .lightning }
}

protocol HasSecurityDomainLogger: HasLogger {}
extension HasSecurityDomainLogger {
    static var logger: Logger { .securityDomain }
}

protocol HasSCPLogger: HasLogger {}
extension HasSCPLogger {
    static var logger: Logger { .scp }
}

protocol HasFIDOLogger: HasLogger {}
extension HasFIDOLogger {
    static var logger: Logger { .fido }
}

extension Logger {
    func traceRequest(
        _ data: @autoclosure () -> Data,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        #if DEBUG
        trace("SEND: \(data().hexEncodedString)", file: file, function: function, line: line)
        #endif
    }

    func traceResponse(
        _ data: @autoclosure () -> Data,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        #if DEBUG
        trace("RECV: \(data().hexEncodedString)", file: file, function: function, line: line)
        #endif
    }

}

extension Logger {
    fileprivate static var nfc: Logger { Logging.logger(category: "NFC") }
    fileprivate static var lightning: Logger { Logging.logger(category: "Lightning") }
    fileprivate static var smartCard: Logger { Logging.logger(category: "SmartCard") }
    fileprivate static var oath: Logger { Logging.logger(category: "OATH") }
    fileprivate static var management: Logger { Logging.logger(category: "Management") }
    fileprivate static var piv: Logger { Logging.logger(category: "PIV") }
    fileprivate static var fido: Logger { Logging.logger(category: "FIDO") }
    fileprivate static var securityDomain: Logger { Logging.logger(category: "SecurityDomain") }
    fileprivate static var scp: Logger { Logging.logger(category: "SCP") }
}
