//
//  ManagementFullStackTests.swift
//  FullStackTestsTests
//
//  Created by Jens Utbult on 2023-01-12.
//

import XCTest
import YubiKit

@testable import FullStackTests

class ManagementFullStackTests: XCTestCase {
    
    func testReadKeyVersion() throws {
        runManagementTest { session, _ in
            print("Got version: \(session.version)")
        }
    }
    
    func testGetDeviceInfo() throws {
        runManagementTest { session, _ in
            let info = try await session.getDeviceInfo()
            print(info)
            print("PIV enabled over usb: \(info.config.isApplicationEnabled(.piv, overTransport: .usb))")
            print("PIV enabled over nfc: \(info.config.isApplicationEnabled(.piv, overTransport: .nfc))")
            print("PIV supported over usb: \(info.isApplicationSupported(.piv, overTransport: .usb))")
            print("PIV supported over nfc: \(info.isApplicationSupported(.piv, overTransport: .nfc))")
        }
    }
    
    func testDisableAndEnableOATH() throws {
        runManagementTest { session, transport in
            try await session.setEnabled(false, application: .oath, overTransport: transport)
            var info = try await session.getDeviceInfo()
            XCTAssertFalse(info.config.isApplicationEnabled(.oath, overTransport: transport))
            let connection = try await ConnectionHelper.anyConnection()
            let oathSession = try? await OATHSession.session(withConnection: connection)
            XCTAssert(oathSession == nil)
            let managementSession = try await ManagementSession.session(withConnection: connection)
            try await managementSession.setEnabled(true, application: .oath, overTransport: transport)
            info = try await managementSession.getDeviceInfo()
            XCTAssert(info.config.isApplicationEnabled(.oath, overTransport: transport))
        }
    }    
}

extension XCTestCase {
    func runManagementTest(named testName: String = #function,
                           in file: StaticString = #file,
                           at line: UInt = #line,
                           withTimeout timeout: TimeInterval = 20,
                           test: @escaping (ManagementSession, DeviceTransport) async throws -> Void) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await ConnectionHelper.anyConnection()
            let transport: DeviceTransport
            if connection as? NFCConnection != nil {
                transport = .nfc
            } else {
                transport = .usb
            }
            let session = try await ManagementSession.session(withConnection: connection)
            try await test(session, transport)
        }
    }
}
