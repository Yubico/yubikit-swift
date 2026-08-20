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

    /// `test_status`, fanned out across both transports the way the Python fixture parameterizes
    /// `[OtpConnection, SmartCardConnection]`.
    public static var parameterizedScenarios: [Scenario] {
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
}

/// One transport row of the OTP scenario families.
private struct OTPTransport: ScenarioParameter, CaseIterable {

    let kind: Scenario.Context.OTPTransportKind

    static var allCases: [OTPTransport] {
        Scenario.Context.OTPTransportKind.allCases.map(OTPTransport.init(kind:))
    }

    var idSuffix: String {
        switch kind {
        case .otpHID: return "otpHID"
        case .smartCard: return "smartCard"
        }
    }

    var displayName: String {
        "serialNumber matches DeviceInfo over \(idSuffix)"
    }

    var requirements: Requirements {
        switch kind {
        case .otpHID:
            return Requirements(capabilities: [.otp], requiresOTPTransport: true)
        case .smartCard:
            return Requirements(capabilities: [.otp])
        }
    }
}
