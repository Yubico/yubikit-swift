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
import YubiKit

/// Yubico OTP scenarios, migrated from yubikey-manager's `tests/device/test_otp.py`.
///
/// The gating mirrors the Python fixtures exactly, including `no_pin_complexity`. That guard has a
/// consequence worth knowing: every TwinKit profile that has the OTP capability also reports PIN
/// complexity on firmware 5.7+, so the programming families **skip by default** on the twin. Run
/// them with `TWIN_PIN_COMPLEXITY=0`:
///
/// ```
/// YUBIKIT_ENABLE_TWINKIT=5-nfc TWIN_PIN_COMPLEXITY=0 swift test --filter ScenarioSuites/OTP
/// ```
public enum OTPScenario: CaseIterable, ScenarioSuite {

    case statusReport

    public var scenario: Scenario {
        switch self {
        // MARK: - Transport
        case .statusReport:
            return Scenario(
                "OTP.Connection.statusReport",
                "an OTP connection reads a status feature report with a plausible firmware version",
                requirements: Requirements(capabilities: [.otp], requiresOTPTransport: true)
            ) { context in
                let connection = try await context.otpConnection()
                let report = Array(try await connection.receive())

                try context.require(
                    report.count == connection.reportSize,
                    "expected a \(connection.reportSize)-byte feature report, got \(report.count)"
                )

                // Layout (yubikit.core.otp): 0 ‖ version[3] ‖ pgmSeq ‖ configState[2, LE] ‖ status.
                context.expectEqual(report[0], 0, "status report should start with a zero byte")

                let major = report[1]
                context.expect(
                    (1...9).contains(major),
                    "firmware major version should be plausible, got \(major)"
                )

                // SLOT_WRITE_FLAG (0x80) clear means the key is ready to accept a frame.
                context.expectEqual(
                    report[7] & 0x80,
                    0,
                    "SLOT_WRITE_FLAG should be clear on an idle key"
                )

                let version = "\(report[1]).\(report[2]).\(report[3])"
                let configState = UInt16(report[5]) | UInt16(report[6]) << 8
                context.log(
                    "OTP status: version \(version), pgmSeq \(report[4]), configState 0x\(String(format: "%04x", configState))"
                )
            }
        }
    }

    /// Every family is fanned out across both transports, the way the Python fixture parameterizes
    /// `[OtpConnection, SmartCardConnection]`.
    public static var parameterizedScenarios: [Scenario] {
        serialScenarios + programmingStateScenarios + touchTriggeredScenarios + ndefScenarios
            + challengeResponseScenarios
    }

    /// `test_status`
    private static var serialScenarios: [Scenario] {
        Scenario.parameterized("OTP.Status.serial", over: OTPTransport.allCases) { context, transport in
            let info = try await context.provider.deviceInfo()

            // Mirrors the Python fixture's skip: 4.x keys do not expose OTP over USB CCID, and
            // 5.x only gained it in 5.3.
            if transport.kind == .smartCard, context.deviceTransport == .usb,
                info.version >= Version("4.0.0")!, info.version < Version("5.3.0")!
            {
                try context.skip("OTP over USB CCID needs firmware < 4.0 or >= 5.3, device is \(info.version)")
            }

            let session = try await context.otpSession(over: transport.kind)
            let serial = try await session.getSerialNumber()
            // Guard against a vacuous pass: both sides reading zero would otherwise compare equal.
            context.expect(serial != 0, "the OTP application should report a non-zero serial")
            context.expectEqual(
                serial,
                info.serialNumber,
                "serial read over \(transport.idSuffix) should match DeviceInfo"
            )

            let state = await session.configState
            context.log("\(transport.idSuffix): serial \(serial), \(state)")
        }
    }

    /// `TestProgrammingState.test_slot_configured`
    private static var programmingStateScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ProgrammingState.slotConfigured",
            // Python gates this class on min_version(2, 1); Java additionally documents swap as a
            // 2.3 feature, but we match Python's declared requirement.
            over: OTPTransport.allCases(minVersion: Version("2.1.0")!)
        ) { context, transport in
            let session = try await Self.programmableSession(context, transport)
            let key = Data(repeating: 0x61, count: 16)

            context.expect(!(await session.configState.isConfigured(.one)), "slot 1 should start empty")
            context.expect(!(await session.configState.isConfigured(.two)), "slot 2 should start empty")

            try await session.putConfiguration(YubiOTP.HMACSHA1SlotConfiguration(key: key), in: .one)
            context.expect(await session.configState.isConfigured(.one), "slot 1 should be configured")
            context.expect(!(await session.configState.isConfigured(.two)), "slot 2 should still be empty")

            try await session.putConfiguration(YubiOTP.HMACSHA1SlotConfiguration(key: key), in: .two)
            context.expect(await session.configState.isConfigured(.one), "slot 1 should stay configured")
            context.expect(await session.configState.isConfigured(.two), "slot 2 should be configured")

            try await session.deleteConfiguration(in: .one)
            context.expect(!(await session.configState.isConfigured(.one)), "slot 1 should be cleared")
            context.expect(await session.configState.isConfigured(.two), "slot 2 should survive")

            try await session.swapConfigurations()
            context.expect(await session.configState.isConfigured(.one), "swap should move slot 2 into slot 1")
            context.expect(!(await session.configState.isConfigured(.two)), "slot 2 should now be empty")

            try await session.deleteConfiguration(in: .one)
            context.expect(!(await session.configState.isConfigured(.one)), "slot 1 should be cleared")
            context.expect(!(await session.configState.isConfigured(.two)), "slot 2 should be cleared")
        }
    }

    /// `test_slot_touch_triggered`, fanned out per slot as well as per transport.
    private static var touchTriggeredScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ProgrammingState.touchTriggered",
            over: OTPTransport.allCases(minVersion: Version("3.0.0")!, perSlot: true)
        ) { context, transport in
            let session = try await Self.programmableSession(context, transport)
            let slot = transport.slot ?? .one

            // A challenge-response slot answers the host, so it is not touch triggered.
            try await session.putConfiguration(
                YubiOTP.HMACSHA1SlotConfiguration(key: Data(repeating: 0x61, count: 16)),
                in: slot
            )
            context.expect(await session.configState.isConfigured(slot), "slot should be configured")
            context.expect(
                !(await session.configState.isTouchTriggered(slot)),
                "a challenge-response slot should not be touch triggered"
            )

            // A static password is typed on touch.
            try await session.putConfiguration(
                YubiOTP.StaticPasswordSlotConfiguration(scanCodes: Data([0x04])),
                in: slot
            )
            context.expect(await session.configState.isConfigured(slot), "slot should still be configured")
            context.expect(
                await session.configState.isTouchTriggered(slot),
                "a static password slot should be touch triggered"
            )

            try await session.deleteConfiguration(in: slot)
            context.expect(!(await session.configState.isConfigured(slot)), "slot should be cleared")
            context.expect(
                !(await session.configState.isTouchTriggered(slot)),
                "a cleared slot should not be touch triggered"
            )
        }
    }

    /// `test_configure_ndef`
    private static var ndefScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ProgrammingState.configureNDEF",
            over: OTPTransport.allCases()
        ) { context, transport in
            let info = try await context.provider.deviceInfo()
            guard info.supportedCapabilities[.nfc] != nil else {
                try context.skip("NDEF requires a device with an NFC interface")
            }
            let session = try await Self.programmableSession(context, transport)

            try await session.putConfiguration(
                YubiOTP.StaticPasswordSlotConfiguration(scanCodes: Data([0x04])),
                in: .one
            )
            try await session.setNDEFConfiguration(in: .one)
            context.log("NDEF configured on slot 1 over \(transport.idSuffix)")
        }
    }

    /// `TestChallengeResponse.test_calculate_hmac_sha1`
    private static var challengeResponseScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ChallengeResponse.hmacSha1",
            over: OTPTransport.allCases(minVersion: Version("2.2.0")!)
        ) { context, transport in
            // `not_usb_ccid`: challenge-response is not exercised over USB CCID.
            if transport.kind == .smartCard, context.deviceTransport == .usb {
                try context.skip("challenge-response is not exercised over USB CCID")
            }
            let session = try await Self.programmableSession(context, transport, clearing: [.two])

            // RFC 2202 test case 1.
            try await session.putConfiguration(
                YubiOTP.HMACSHA1SlotConfiguration(key: Data(repeating: 0x0B, count: 20)),
                in: .two
            )
            let response = try await session.calculateHMACSHA1(challenge: Data("Hi There".utf8), in: .two)
                .value
            context.expectEqual(
                response.hexString,
                "b617318655057264e28bc0b6fb378c8ef146be00",
                "HMAC-SHA1 should match the RFC 2202 vector"
            )
        }
    }

    /// A session with both slots cleared, plus teardown that clears them again. Mirrors the Python
    /// `clear_slots` autouse fixture, including its PIN-complexity guard.
    private static func programmableSession(
        _ context: Scenario.Context,
        _ transport: OTPTransport,
        clearing slots: [YubiOTP.Slot] = YubiOTP.Slot.allCases
    ) async throws -> YubiOTP.Session {
        let info = try await context.provider.deviceInfo()
        if info.pinComplexity {
            try context.skip("programming OTP slots is blocked while PIN complexity is enforced")
        }
        if transport.kind == .smartCard, context.deviceTransport == .usb,
            info.version >= Version("4.0.0")!, info.version < Version("5.3.0")!
        {
            try context.skip("OTP over USB CCID needs firmware < 4.0 or >= 5.3, device is \(info.version)")
        }

        let session = try await context.otpSession(over: transport.kind)
        for slot in slots where await session.configState.isConfigured(slot) {
            try await session.deleteConfiguration(in: slot)
        }
        await context.addTeardown {
            for slot in slots where await session.configState.isConfigured(slot) {
                try await session.deleteConfiguration(in: slot)
            }
        }
        return session
    }
}

/// One transport row of the OTP scenario families.
private struct OTPTransport: ScenarioParameter {

    let kind: Scenario.Context.OTPTransportKind
    let slot: YubiOTP.Slot?
    let minVersion: Version?

    static var allCases: [OTPTransport] { allCases() }

    /// One row per transport, optionally multiplied by slot the way
    /// `@pytest.mark.parametrize("slot", [SLOT.ONE, SLOT.TWO])` does.
    static func allCases(minVersion: Version? = nil, perSlot: Bool = false) -> [OTPTransport] {
        let slots: [YubiOTP.Slot?] = perSlot ? YubiOTP.Slot.allCases : [nil]
        return Scenario.Context.OTPTransportKind.allCases.flatMap { kind in
            slots.map { OTPTransport(kind: kind, slot: $0, minVersion: minVersion) }
        }
    }

    var idSuffix: String {
        let transport = kind == .otpHID ? "otpHID" : "smartCard"
        guard let slot else { return transport }
        return "\(transport).slot\(slot.rawValue)"
    }

    var displayName: String { idSuffix }

    var requirements: Requirements {
        Requirements(
            capabilities: [.otp],
            minVersion: minVersion,
            requiresOTPTransport: kind == .otpHID
        )
    }
}
