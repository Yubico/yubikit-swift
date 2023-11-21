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

import XCTest
import YubiKit

@testable import FullStackTests

class ManagementFullStackTests: XCTestCase {
    
    func testReadKeyVersion() throws {
        runManagementTest { connection, session, _ in
            print("✅ Got version: \(session.version)")
            #if os(iOS)
            await connection.nfcConnection?.close(message: "YubiKey Version \(session.version)")
            #endif
            XCTAssertNotNil(session.version)
        }
    }
    
    func testGetDeviceInfo() throws {
        runManagementTest { _, session, _ in
            let info = try await session.getDeviceInfo()
            print(info)
            print("PIV enabled over usb: \(info.config.isApplicationEnabled(.piv, overTransport: .usb))")
            print("PIV enabled over nfc: \(info.config.isApplicationEnabled(.piv, overTransport: .nfc))")
            print("PIV supported over usb: \(info.isApplicationSupported(.piv, overTransport: .usb))")
            print("PIV supported over nfc: \(info.isApplicationSupported(.piv, overTransport: .nfc))")
        }
    }
    
    func testDisableAndEnableOATH() throws {
        runManagementTest { connection, session, transport in
            try await session.setEnabled(false, application: .oath, overTransport: transport)
            var info = try await session.getDeviceInfo()
            XCTAssertFalse(info.config.isApplicationEnabled(.oath, overTransport: transport))
            let oathSession = try? await OATHSession.session(withConnection: connection)
            XCTAssert(oathSession == nil)
            let managementSession = try await ManagementSession.session(withConnection: connection)
            try await managementSession.setEnabled(true, application: .oath, overTransport: transport)
            info = try await managementSession.getDeviceInfo()
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
            XCTAssert(info.config.isApplicationEnabled(.oath, overTransport: transport))
        }
    }    
}

extension XCTestCase {
    func runManagementTest(named testName: String = #function,
                           in file: StaticString = #file,
                           at line: UInt = #line,
                           withTimeout timeout: TimeInterval = 20,
                           test: @escaping (Connection, ManagementSession, DeviceTransport) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await ConnectionHelper.anyConnection(nfcAlertMessage: "Running Management Tests...")
            let transport: DeviceTransport
            #if os(iOS)
            if connection as? NFCConnection != nil {
                transport = .nfc
            } else {
                transport = .usb
            }
            #else
            transport = .usb
            #endif
            
            let session = try await ManagementSession.session(withConnection: connection)
            try await test(connection, session, transport)
        }
    }
}
