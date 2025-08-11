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

@testable import FullStackTests
@testable import YubiKit

private let lockCode = Data(hexEncodedString: "01020304050607080102030405060708")!
private let clearLockCode = Data(hexEncodedString: "00000000000000000000000000000000")!

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
        runManagementTest { connection, session, _ in
            let info = try await session.getDeviceInfo()
            print("✅ Successfully got device info:\n\(info)")
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    func testTimeouts() throws {
        runManagementTest { connection, session, _ in
            let deviceInfo = try await session.getDeviceInfo()
            let config = deviceInfo.config.deviceConfig(autoEjectTimeout: 320.0, challengeResponseTimeout: 135.0)
            try await session.updateDeviceConfig(config, reboot: false)
            let info = try await session.getDeviceInfo()
            XCTAssertEqual(info.config.challengeResponseTimeout, 135.0)
            XCTAssertEqual(info.config.autoEjectTimeout, 320.0)
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    func testDisableAndEnableConfigOATHandPIVoverUSB() throws {
        runManagementTest { connection, session, transport in
            let deviceInfo = try await session.getDeviceInfo()
            guard
                let disableConfig = deviceInfo.config.deviceConfig(
                    enabling: false,
                    application: .OATH,
                    overTransport: .usb
                )?.deviceConfig(enabling: false, application: .PIV, overTransport: .usb)
            else {
                XCTFail()
                return
            }
            try await session.updateDeviceConfig(disableConfig, reboot: false)
            let disabledInfo = try await session.getDeviceInfo()
            XCTAssertFalse(disabledInfo.config.isApplicationEnabled(.OATH, overTransport: .usb))
            XCTAssertFalse(disabledInfo.config.isApplicationEnabled(.PIV, overTransport: .usb))
            let oathSession = try? await OATHSession.session(withConnection: connection)
            if transport == .usb {
                XCTAssert(oathSession == nil)
            }
            let managementSession = try await ManagementSession.session(withConnection: connection)
            guard
                let enableConfig = deviceInfo.config.deviceConfig(
                    enabling: true,
                    application: .OATH,
                    overTransport: .usb
                )?.deviceConfig(enabling: true, application: .PIV, overTransport: .usb)
            else {
                XCTFail()
                return
            }
            try await managementSession.updateDeviceConfig(enableConfig, reboot: false)
            let enabledInfo = try await managementSession.getDeviceInfo()
            XCTAssert(enabledInfo.config.isApplicationEnabled(.OATH, overTransport: .usb))
            XCTAssert(enabledInfo.config.isApplicationEnabled(.PIV, overTransport: .usb))
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    func testDisableAndEnableConfigOATHandPIVoverNFC() throws {
        runManagementTest { connection, session, transport in
            let deviceInfo = try await session.getDeviceInfo()
            guard deviceInfo.hasTransport(.nfc) else {
                print("⚠️ No NFC YubiKey. Skip test.")
                return
            }
            guard
                let disableConfig = deviceInfo.config.deviceConfig(
                    enabling: false,
                    application: .OATH,
                    overTransport: .nfc
                )?.deviceConfig(enabling: false, application: .PIV, overTransport: .nfc)
            else {
                XCTFail()
                return
            }
            try await session.updateDeviceConfig(disableConfig, reboot: false)
            let disabledInfo = try await session.getDeviceInfo()
            XCTAssertFalse(disabledInfo.config.isApplicationEnabled(.OATH, overTransport: .nfc))
            XCTAssertFalse(disabledInfo.config.isApplicationEnabled(.PIV, overTransport: .nfc))
            let oathSession = try? await OATHSession.session(withConnection: connection)
            if transport == .nfc {
                XCTAssert(oathSession == nil)
            }
            let managementSession = try await ManagementSession.session(withConnection: connection)
            guard
                let enableConfig = deviceInfo.config.deviceConfig(
                    enabling: true,
                    application: .OATH,
                    overTransport: .nfc
                )?.deviceConfig(enabling: true, application: .PIV, overTransport: .nfc)
            else {
                XCTFail()
                return
            }
            try await managementSession.updateDeviceConfig(enableConfig, reboot: false)
            let enabledInfo = try await managementSession.getDeviceInfo()
            XCTAssert(enabledInfo.config.isApplicationEnabled(.OATH, overTransport: .nfc))
            XCTAssert(enabledInfo.config.isApplicationEnabled(.PIV, overTransport: .nfc))
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    func testDisableAndEnableWithHelperOATH() throws {
        runManagementTest { connection, session, transport in
            try await session.setEnabled(false, application: .OATH, overTransport: transport)
            var info = try await session.getDeviceInfo()
            XCTAssertFalse(info.config.isApplicationEnabled(.OATH, overTransport: transport))
            let oathSession = try? await OATHSession.session(withConnection: connection)
            XCTAssert(oathSession == nil)
            let managementSession = try await ManagementSession.session(withConnection: connection)
            try await managementSession.setEnabled(true, application: .OATH, overTransport: transport)
            info = try await managementSession.getDeviceInfo()
            XCTAssert(info.config.isApplicationEnabled(.OATH, overTransport: transport))
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    func testLockCode() throws {
        runManagementTest { connection, session, transport in
            let config = try await session.getDeviceInfo().config
            do {
                try await session.updateDeviceConfig(config, reboot: false, newLockCode: lockCode)
                print("✅ Lock code set to: \(lockCode.hexEncodedString)")
            } catch {
                XCTFail("Failed setting new lock code")
            }
            do {
                try await session.updateDeviceConfig(
                    config.deviceConfig(enabling: false, application: .OATH, overTransport: .usb)!,
                    reboot: false
                )
                XCTFail(
                    "Successfully updated config although no lock code was supplied and it should have been enabled."
                )
            } catch {
                print("✅ Failed updating device config (as expected) without using lock code.")
            }
            do {
                try await session.updateDeviceConfig(
                    config.deviceConfig(enabling: false, application: .OATH, overTransport: .usb)!,
                    reboot: false,
                    lockCode: lockCode
                )
                print("✅ Succesfully updated device config using lock code.")
            } catch {
                XCTFail("Failed to update device config even though lock code was supplied.")
            }
        }
    }

    // Tests are run in alphabetical order. If running the tests via NFC this will disable NFC for all the following tests making them fail, hence the Z in the name.
    func testZNFCRestricted() throws {
        runManagementTest { connection, session, transport in
            guard session.version >= Version(withString: "5.7.0")! else {
                print("⚠️ YubiKey without support for NFC restricted. Skip test.")
                return
            }
            let info = try await session.getDeviceInfo()
            let newConfig = info.config.deviceConfig(nfcRestricted: true)
            try await session.updateDeviceConfig(newConfig, reboot: false)
            let updatedInfo = try await session.getDeviceInfo()
            XCTAssertEqual(updatedInfo.config.isNFCRestricted, true)
            if transport == .nfc {
                #if os(iOS)
                await connection.nfcConnection?.close(
                    message: "NFC is now restriced until this YubiKey has been inserted into a USB port."
                )
                do {
                    let newConnection = try await TestableConnections.create()
                    _ = try await ManagementSession.session(withConnection: newConnection)
                    XCTFail("Got connection even if NFC restriced was turned on!")
                } catch {
                    print("✅ Failed creating ManagementSession as expected.")
                }
                #endif
            }
            print("✅ NFC is now restriced until this YubiKey has been inserted into a USB port.")
            print(
                "⚠️ Note that no more NFC testing will be possible until NFC restriction has been disabled for this key!"
            )
        }
    }

    func testBioDeviceReset() throws {
        runManagementTest { connection, session, transport in
            let deviceInfo = try await session.getDeviceInfo()
            guard deviceInfo.formFactor == .usbCBio || deviceInfo.formFactor == .usbABio else {
                print("⚠️ Skip testBioDeviceReset()")
                return
            }
            try await session.deviceReset()
            var pivSession = try await PIVSession.session(withConnection: connection)
            var pinMetadata = try await pivSession.getPinMetadata()
            XCTAssertTrue(pinMetadata.isDefault)
            try await pivSession.setPin("654321", oldPin: "123456")
            pinMetadata = try await pivSession.getPinMetadata()
            XCTAssertFalse(pinMetadata.isDefault)
            let managementSession = try await ManagementSession.session(withConnection: connection)
            try await managementSession.deviceReset()
            pivSession = try await PIVSession.session(withConnection: connection)
            pinMetadata = try await pivSession.getPinMetadata()
            XCTAssertTrue(pinMetadata.isDefault)
        }
    }
}

extension XCTestCase {
    func runManagementTest(
        named testName: String = #function,
        in file: StaticString = #file,
        at line: UInt = #line,
        withTimeout timeout: TimeInterval = 20,
        test: @escaping (SmartCardConnection, ManagementSession, DeviceTransport) async throws -> Void
    ) {
        runAsyncTest(named: testName, in: file, at: line, withTimeout: timeout) {
            let connection = try await TestableConnections.create()
            let transport: DeviceTransport
            #if os(iOS)
            if connection as? NFCSmartCardConnection != nil {
                transport = .nfc
            } else {
                transport = .usb
            }
            #else
            transport = .usb
            #endif

            let session = try await ManagementSession.session(withConnection: connection)
            let config = try await session.getDeviceInfo().config
            // Try removing the lock code.
            try? await session.updateDeviceConfig(config, reboot: false, lockCode: lockCode, newLockCode: clearLockCode)
            try await test(connection, session, transport)
        }
    }
}
