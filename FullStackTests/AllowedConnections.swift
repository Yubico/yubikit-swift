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
import OSLog
import XCTest
import YubiKit

extension Connection {
    func isAllowed() async throws -> Bool {
        guard let path = Bundle(for: OATHFullStackTests.self).path(forResource: "allowed-yubikeys", ofType: "csv"),
            let contents = try? String(contentsOfFile: path)
        else { fatalError("No allowed-yubikeys.csv file") }
        let allowedList = contents.components(separatedBy: ",\n").map {
            UInt($0.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        let session = try await ManagementSession.session(withConnection: self)
        let deviceInfo = try await session.getDeviceInfo()
        Logger.test.info("Checking if YubiKey with serial '\(deviceInfo.serialNumber)' is in allow list.")
        return allowedList.contains(deviceInfo.serialNumber)
    }
}

public enum AllowedConnections {

    public static func anyConnection(nfcAlertMessage: String? = nil) async throws -> Connection {
        let connection = try await ConnectionHelper.anyConnection(nfcAlertMessage: nfcAlertMessage)
        let isAllowed = try await connection.isAllowed()
        XCTAssertTrue(isAllowed, "YubiKey is not in allowed connections list.")
        return connection
    }

    public static func anyWiredConnection() async throws -> Connection {
        let connection = try await ConnectionHelper.anyWiredConnection()
        let isAllowed = try await connection.isAllowed()
        XCTAssertTrue(isAllowed, "YubiKey is not in allowed connections list.")
        return connection
    }

    public static func wiredConnections() -> AllowedConnections.AnyWiredConnections {
        AnyWiredConnections()
    }

    public struct AnyWiredConnections: AsyncSequence {
        public typealias Element = Connection
        var current: Connection? = nil
        public struct AsyncIterator: AsyncIteratorProtocol {
            mutating public func next() async -> Element? {
                while true {
                    return try? await AllowedConnections.anyWiredConnection()
                }
            }
        }

        public func makeAsyncIterator() -> AsyncIterator {
            AsyncIterator()
        }
    }
}
