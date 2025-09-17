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
import Testing

@testable import FullStackTests
@testable import YubiKit

private let lockCode = Data(hexEncodedString: "01020304050607080102030405060708")!
private let clearLockCode = Data(hexEncodedString: "00000000000000000000000000000000")!

@Suite("Management Full Stack Tests", .serialized)
struct ManagementFullStackTests {

    // MARK: - Device Information Tests

    @Test("Read YubiKey version")
    func readKeyVersion() async throws {
        try await runManagementTest { connection, session, _ in
            let version = await session.version
            trace("Got version: \(version)")
            #if os(iOS)
            await connection.nfcConnection?.close(message: "YubiKey Version \(session.version)")
            #endif
        }
    }

    @Test("Get device information")
    func getDeviceInfo() async throws {
        try await runManagementTest { connection, session, _ in
            let info = try await session.getDeviceInfo()
            trace("Successfully got device info:\n\(info)")
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    // MARK: - Configuration Tests

    @Test("Configure timeouts")
    func timeouts() async throws {
        try await runManagementTest { connection, session, _ in
            let deviceInfo = try await session.getDeviceInfo()
            let config = deviceInfo.config.with(autoEjectTimeout: 320.0, challengeResponseTimeout: 135.0)
            try await session.updateDeviceConfig(config, reboot: false)
            let info = try await session.getDeviceInfo()
            #expect(info.config.challengeResponseTimeout == 135.0)
            #expect(info.config.autoEjectTimeout == 320.0)
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    @Test("Disable and enable OATH/PIV over USB")
    func disableAndEnableConfigOATHandPIVoverUSB() async throws {
        try await runManagementTest { connection, session, transport in
            let deviceInfo = try await session.getDeviceInfo()
            guard
                let disableConfig = deviceInfo.config.disable(
                    application: .oath,
                    over: .usb
                )?.disable(application: .piv, over: .usb)
            else {
                Issue.record("Expected valid config")
                return
            }
            try await session.updateDeviceConfig(disableConfig, reboot: false)
            let disabledInfo = try await session.getDeviceInfo()
            #expect(!disabledInfo.config.isApplicationEnabled(.oath, over: .usb))
            #expect(!disabledInfo.config.isApplicationEnabled(.piv, over: .usb))
            let oathSession = try? await OATHSession.makeSession(connection: connection)
            if transport == .usb {
                #expect(oathSession == nil)
            }
            let managementSession = try await ManagementSession.makeSession(connection: connection)
            guard
                let enableConfig = deviceInfo.config.enable(
                    application: .oath,
                    over: .usb
                )?.enable(application: .piv, over: .usb)
            else {
                Issue.record("Expected valid config")
                return
            }
            try await managementSession.updateDeviceConfig(enableConfig, reboot: false)
            let enabledInfo = try await managementSession.getDeviceInfo()
            #expect(enabledInfo.config.isApplicationEnabled(.oath, over: .usb))
            #expect(enabledInfo.config.isApplicationEnabled(.piv, over: .usb))
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    @Test("Disable and enable OATH/PIV over NFC")
    func disableAndEnableConfigOATHandPIVoverNFC() async throws {
        try await runManagementTest { connection, session, transport in
            let deviceInfo = try await session.getDeviceInfo()
            guard deviceInfo.hasTransport(.nfc) else {
                reportSkip(reason: "No NFC YubiKey")
                return
            }
            guard
                let disableConfig = deviceInfo.config.disable(
                    application: .oath,
                    over: .nfc
                )?.disable(application: .piv, over: .nfc)
            else {
                Issue.record("Expected valid config")
                return
            }
            try await session.updateDeviceConfig(disableConfig, reboot: false)
            let disabledInfo = try await session.getDeviceInfo()
            #expect(!disabledInfo.config.isApplicationEnabled(.oath, over: .nfc))
            #expect(!disabledInfo.config.isApplicationEnabled(.piv, over: .nfc))
            let oathSession = try? await OATHSession.makeSession(connection: connection)
            if transport == .nfc {
                #expect(oathSession == nil)
            }
            let managementSession = try await ManagementSession.makeSession(connection: connection)
            guard
                let enableConfig = deviceInfo.config.enable(
                    application: .oath,
                    over: .nfc
                )?.enable(application: .piv, over: .nfc)
            else {
                Issue.record("Expected valid config")
                return
            }
            try await managementSession.updateDeviceConfig(enableConfig, reboot: false)
            let enabledInfo = try await managementSession.getDeviceInfo()
            #expect(enabledInfo.config.isApplicationEnabled(.oath, over: .nfc))
            #expect(enabledInfo.config.isApplicationEnabled(.piv, over: .nfc))
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    @Test("Disable and enable OATH with helper")
    func disableAndEnableWithHelperOATH() async throws {
        try await runManagementTest { connection, session, transport in
            try await session.disableApplication(.oath, over: transport)
            var info = try await session.getDeviceInfo()
            #expect(!info.config.isApplicationEnabled(.oath, over: transport))
            let oathSession = try? await OATHSession.makeSession(connection: connection)
            #expect(oathSession == nil)
            let managementSession = try await ManagementSession.makeSession(connection: connection)
            try await managementSession.enableApplication(.oath, over: transport)
            info = try await managementSession.getDeviceInfo()
            #expect(info.config.isApplicationEnabled(.oath, over: transport))
            #if os(iOS)
            await connection.nfcConnection?.close(message: "Test successful!")
            #endif
        }
    }

    // MARK: - Security Tests

    @Test("Set and use lock code")
    func setAndUseLockCode() async throws {
        try await runManagementTest { connection, session, transport in
            let config = try await session.getDeviceInfo().config
            do {
                try await session.updateDeviceConfig(config, reboot: true, newLockCode: lockCode)
                trace("Lock code set to: \(lockCode.hexEncodedString)")
            } catch {
                Issue.record("Failed setting new lock code")
            }
            do {
                try await session.updateDeviceConfig(
                    config.disable(application: .oath, over: .usb)!,
                    reboot: false
                )
                Issue.record(
                    "Successfully updated config although no lock code was supplied and it should have been enabled."
                )
            } catch {
                trace("Failed updating device config (as expected) without using lock code.")
            }
            do {
                try await session.updateDeviceConfig(
                    config.disable(application: .oath, over: .usb)!,
                    reboot: false,
                    lockCode: lockCode
                )
                trace("Successfully updated device config using lock code.")
            } catch {
                Issue.record("Failed to update device config even though lock code was supplied.")
            }
        }
    }

    // Tests are run in alphabetical order. If running the tests via NFC this will disable NFC for all the following tests making them fail, hence the Z in the name.
    @Test("Enable NFC restriction")
    func nfcRestricted() async throws {
        try await runManagementTest { connection, session, transport in
            guard await session.version >= Version("5.7.0")! else {
                reportSkip(reason: "YubiKey version too old")
                return
            }
            let info = try await session.getDeviceInfo()
            let newConfig = info.config.with(nfcRestricted: true)
            try await session.updateDeviceConfig(newConfig, reboot: false)
            let updatedInfo = try await session.getDeviceInfo()
            #expect(updatedInfo.config.isNFCRestricted == true)
            if transport == .nfc {
                #if os(iOS)
                await connection.nfcConnection?.close(
                    message: "NFC is now restricted until this YubiKey has been inserted into a USB port."
                )
                do {
                    let newConnection = try await TestableConnection.shared()
                    _ = try await ManagementSession.makeSession(connection: newConnection)
                    Issue.record("Got connection even if NFC restricted was turned on!")
                } catch {
                    trace("Failed creating ManagementSession as expected.")
                }
                #endif
            }
            trace("NFC is now restricted until this YubiKey has been inserted into a USB port.")
            trace(
                "Note that no more NFC testing will be possible until NFC restriction has been disabled for this key!"
            )
        }
    }

    // MARK: - Reset Tests

    @Test("Bio device reset")
    func bioDeviceReset() async throws {
        try await runManagementTest { connection, session, transport in
            let deviceInfo = try await session.getDeviceInfo()
            guard deviceInfo.formFactor == .usbCBio || deviceInfo.formFactor == .usbABio else {
                reportSkip(reason: "Not a YubiKey Bio device")
                return
            }
            try await session.resetDevice()
            var pivSession = try await PIVSession.makeSession(connection: connection)
            var pinMetadata = try await pivSession.getPinMetadata()
            #expect(pinMetadata.isDefault)
            try await pivSession.changePin(from: "123456", to: "654321")
            pinMetadata = try await pivSession.getPinMetadata()
            #expect(!pinMetadata.isDefault)
            let managementSession = try await ManagementSession.makeSession(connection: connection)
            try await managementSession.resetDevice()
            pivSession = try await PIVSession.makeSession(connection: connection)
            pinMetadata = try await pivSession.getPinMetadata()
            #expect(pinMetadata.isDefault)
        }
    }
}

// MARK: - Helpers
private func runManagementTest(
    test: (SmartCardConnection, ManagementSession, DeviceTransport) async throws -> Void
) async throws {
    try await Task.sleep(for: .seconds(5))  // Give some time between tests to avoid issues with NFC
    let connection = try await TestableConnection.shared()
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

    let session = try await ManagementSession.makeSession(connection: connection)
    let config = try await session.getDeviceInfo().config
    // Try removing the lock code.
    try? await session.updateDeviceConfig(config, reboot: false, lockCode: lockCode, newLockCode: clearLockCode)
    try await test(connection, session, transport)
}
