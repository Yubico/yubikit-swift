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

enum OTPScenario {

    static var allScenarios: [Scenario] {
        serialScenarios + programmingStateScenarios + touchTriggeredScenarios + ndefScenarios
            + updateScenarios + challengeResponseScenarios + touchScenarios + accessCodeScenarios
    }

    // MARK: - Status

    private static var serialScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.Status.serial",
            "getSerialNumber matches the device serial",
            over: OTPTransport.allCases
        ) { context, transport in
            try await skipUnsupportedTransport(context, transport, needsSlotState: false)

            let session = try await context.otpSession(over: transport.kind)
            let serial = try await session.getSerialNumber()
            context.expect(serial != 0, "the OTP application should report a non-zero serial")
            context.expectEqual(
                serial,
                try await context.provider.deviceInfo().serialNumber,
                "serial read over \(transport.idSuffix) should match DeviceInfo"
            )
            context.log("\(transport.idSuffix): serial \(serial), \(await session.configState)")
        }
    }

    // MARK: - Programming state

    private static var programmingStateScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ProgrammingState.slotConfigured",
            "slot state tracks programming, deletion, and swapping",
            over: OTPTransport.allCases(minVersion: Version("2.3.0")!)
        ) { context, transport in
            let session = try await programmableSession(context, transport)
            let key = Data(repeating: 0x61, count: 16)

            context.expect(try !(await session.configState).isConfigured(.one), "slot 1 should start empty")
            context.expect(try !(await session.configState).isConfigured(.two), "slot 2 should start empty")

            try await session.putConfiguration(.hmacSHA1(key: key), in: .one)
            context.expect(try await session.configState.isConfigured(.one), "slot 1 should be configured")
            context.expect(try !(await session.configState).isConfigured(.two), "slot 2 should still be empty")

            try await session.putConfiguration(.hmacSHA1(key: key), in: .two)
            context.expect(try await session.configState.isConfigured(.one), "slot 1 should stay configured")
            context.expect(try await session.configState.isConfigured(.two), "slot 2 should be configured")

            try await session.deleteConfiguration(in: .one)
            context.expect(try !(await session.configState).isConfigured(.one), "slot 1 should be cleared")
            context.expect(try await session.configState.isConfigured(.two), "slot 2 should survive")

            try await session.swapConfigurations()
            context.expect(try await session.configState.isConfigured(.one), "swap should move slot 2 into slot 1")
            context.expect(try !(await session.configState).isConfigured(.two), "slot 2 should now be empty")

            try await session.deleteConfiguration(in: .one)
            context.expect(try !(await session.configState).isConfigured(.one), "slot 1 should be cleared")
            context.expect(try !(await session.configState).isConfigured(.two), "slot 2 should be cleared")
        }
    }

    private static var touchTriggeredScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ProgrammingState.touchTriggered",
            "touch-triggered state follows the slot configuration",
            over: OTPTransport.allCases(minVersion: Version("3.0.0")!, perSlot: true)
        ) { context, transport in
            let session = try await programmableSession(context, transport)
            let slot = transport.slot ?? .one

            try await session.putConfiguration(.hmacSHA1(key: Data(repeating: 0x61, count: 16)), in: slot)
            context.expect(try await session.configState.isConfigured(slot), "slot should be configured")
            context.expect(
                try !(await session.configState).isTouchTriggered(slot),
                "a challenge-response slot should not be touch triggered"
            )

            try await session.putConfiguration(.staticPassword(scanCodes: Data([0x04])), in: slot)
            context.expect(try await session.configState.isConfigured(slot), "slot should still be configured")
            context.expect(
                try await session.configState.isTouchTriggered(slot),
                "a static password slot should be touch triggered"
            )

            try await session.deleteConfiguration(in: slot)
            context.expect(try !(await session.configState).isConfigured(slot), "slot should be cleared")
            context.expect(
                try !(await session.configState).isTouchTriggered(slot),
                "a cleared slot should not be touch triggered"
            )
        }
    }

    private static var ndefScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ProgrammingState.configureNDEF",
            "setNDEFConfiguration configures a slot for NFC output",
            over: OTPTransport.allCases(minVersion: Version("3.0.0")!)
        ) { context, transport in
            guard try await context.provider.deviceInfo().supportedCapabilities[.nfc] != nil else {
                try context.skip("NDEF requires a device with an NFC interface")
            }
            let session = try await programmableSession(context, transport)

            try await session.putConfiguration(.staticPassword(scanCodes: Data([0x04])), in: .one)
            try await session.setNDEFConfiguration(in: .one)
        }
    }

    private static var updateScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ProgrammingState.updateConfiguration",
            "updateConfiguration rejects empty slots and preserves slot state",
            over: OTPTransport.allCases(minVersion: Version("2.3.0")!)
        ) { context, transport in
            let session = try await programmableSession(context, transport)

            await context.expectThrows(
                "updating an unprogrammed slot",
                matching: { if case YubiOTP.SessionError.commandRejected = $0 { true } else { false } }
            ) {
                try await session.updateConfiguration(YubiOTP.SlotUpdate(), in: .one)
            }

            try await session.putConfiguration(.hmacSHA1(key: Data(repeating: 0x61, count: 16)), in: .one)
            try await session.updateConfiguration(
                YubiOTP.SlotUpdate(
                    tabs: .init(beforeFirst: true, afterFirst: true),
                    delays: .init(afterSecond: true)
                ),
                in: .one
            )
            context.expect(try await session.configState.isConfigured(.one), "slot 1 should survive the update")
            context.expect(
                try !(await session.configState).isTouchTriggered(.one),
                "an update must not turn a challenge-response slot into a touch-triggered one"
            )
        }
    }

    // MARK: - Challenge-response

    private static var challengeResponseScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.ChallengeResponse.hmacSha1",
            "HMAC-SHA1 matches the RFC 2202 test vector",
            over: OTPTransport.allCases(minVersion: Version("2.2.0")!)
        ) { context, transport in
            if try await usesUSBCCID(context, transport) {
                try context.skip("HMAC-SHA1 challenge-response is not available over USB CCID")
            }
            let session = try await programmableSession(context, transport, clearing: [.two])

            try await session.putConfiguration(.hmacSHA1(key: hmacKey), in: .two)
            let response = try await session.calculateHMACSHA1(challenge: hmacChallenge, in: .two).value
            context.expectEqual(response.hexString, hmacResponse, "HMAC-SHA1 should match the RFC 2202 vector")
        }
    }

    // Only the OTP keyboard transport reports a pending touch and can cancel it.
    private static var touchScenarios: [Scenario] {
        let transports = [OTPTransport(kind: .otpHID, slot: nil, minVersion: Version("2.2.0")!)]
        let touch = Scenario.parameterized(
            "OTP.ChallengeResponse.touch",
            "HMAC-SHA1 reports a pending touch and returns the expected response",
            over: transports
        ) { context, transport in
            let session = try await programmableSession(context, transport, clearing: [.two])
            try await session.putConfiguration(.hmacSHA1(key: hmacKey, requireTouch: true), in: .two)

            context.touch("Touch the key to answer the HMAC-SHA1 challenge")
            var sawTouch = false
            for try await status in await session.calculateHMACSHA1(challenge: hmacChallenge, in: .two) {
                switch status {
                case .processing:
                    break
                case .waitingForUser:
                    sawTouch = true
                case .finished(let response):
                    context.expectEqual(response.hexString, hmacResponse, "HMAC-SHA1 should match the RFC 2202 vector")
                }
            }
            context.expect(sawTouch, "a touch-triggered slot should report the pending touch")
        }
        let cancel = Scenario.parameterized(
            "OTP.ChallengeResponse.cancelTouch",
            "cancelling a pending touch keeps the session usable",
            over: transports
        ) { context, transport in
            let session = try await programmableSession(context, transport, clearing: [.two])
            try await session.putConfiguration(.hmacSHA1(key: hmacKey, requireTouch: true), in: .two)

            context.touch("DO NOT touch the key — the challenge will be cancelled")
            await context.expectThrows(
                "a cancelled challenge",
                matching: { if case YubiOTP.SessionError.cancelled = $0 { true } else { false } }
            ) {
                for try await status in await session.calculateHMACSHA1(challenge: hmacChallenge, in: .two) {
                    if case .waitingForUser(let cancel) = status { await cancel() }
                }
            }

            // The same session must stay usable after a cancel.
            try await session.putConfiguration(.hmacSHA1(key: hmacKey), in: .two)
            let response = try await session.calculateHMACSHA1(challenge: hmacChallenge, in: .two).value
            context.expectEqual(response.hexString, hmacResponse, "HMAC-SHA1 after a cancel should still succeed")
        }
        return touch + cancel
    }

    // MARK: - Access code

    private static var accessCodeScenarios: [Scenario] {
        Scenario.parameterized(
            "OTP.AccessCode.lifecycle",
            "access codes protect slot writes and can be changed or removed",
            over: OTPTransport.allCases(minVersion: Version("2.3.0")!)
        ) { context, transport in
            try await skipUnsupportedTransport(context, transport)

            let codeA = try YubiOTP.AccessCode(Data([1, 2, 3, 4, 5, 6]))
            let codeB = try YubiOTP.AccessCode(Data([6, 5, 4, 3, 2, 1]))
            let wrongCode = try YubiOTP.AccessCode(Data([9, 8, 7, 6, 5, 4]))
            let configuration = try YubiOTP.SlotConfiguration.hmacSHA1(key: hmacKey)
            let update = try YubiOTP.SlotUpdate(tabs: .init(beforeFirst: true))
            let session = try await context.otpSession(over: transport.kind)
            try context.require(
                try !(await session.configState).isConfigured(.two),
                "access-code tests require empty slot 2"
            )

            // A write can reach the key even when its response fails, so try each code that the
            // scenario sets.
            await context.addTeardown {
                for code in [nil, codeA, codeB] as [YubiOTP.AccessCode?] {
                    let cleanup = try await context.otpSession(over: transport.kind)
                    guard try await cleanup.configState.isConfigured(.two) else { return }
                    try? await cleanup.deleteConfiguration(in: .two, currentAccessCode: code)
                }
                let fresh = try await context.otpSession(over: transport.kind)
                try context.require(try !(await fresh.configState).isConfigured(.two), "teardown should clear slot 2")
            }

            try await session.putConfiguration(configuration, in: .two, accessCode: .set(codeA))
            try await verifyHMACSecret(context, transport, session: session)

            for code in [nil, wrongCode] as [YubiOTP.AccessCode?] {
                await context.expectThrows("put with a missing or wrong access code", matching: isAccessDenied) {
                    try await session.putConfiguration(configuration, in: .two, currentAccessCode: code)
                }
                await context.expectThrows("update with a missing or wrong access code", matching: isAccessDenied) {
                    try await session.updateConfiguration(update, in: .two, currentAccessCode: code)
                }
                await context.expectThrows("delete with a missing or wrong access code", matching: isAccessDenied) {
                    try await session.deleteConfiguration(in: .two, currentAccessCode: code)
                }
            }

            try await session.putConfiguration(configuration, in: .two, currentAccessCode: codeA)
            await context.expectThrows("update after a put that preserved the code", matching: isAccessDenied) {
                try await session.updateConfiguration(update, in: .two)
            }
            try await session.updateConfiguration(update, in: .two, currentAccessCode: codeA)
            await context.expectThrows("delete after an update that preserved the code", matching: isAccessDenied) {
                try await session.deleteConfiguration(in: .two)
            }
            try await verifyHMACSecret(context, transport, session: session)

            // Firmware 4.3.2–4.3.5 cannot change the access code through UPDATE.
            let version = await session.version
            let canUpdateCode = version < Version("4.3.2")! || version >= Version("4.3.6")!
            if canUpdateCode {
                try await session.updateConfiguration(
                    update,
                    in: .two,
                    accessCode: .set(codeB),
                    currentAccessCode: codeA
                )
            } else {
                await context.expectThrows(
                    "changing the access code through UPDATE on \(version)",
                    matching: { if case YubiOTP.SessionError.featureNotSupported = $0 { true } else { false } }
                ) {
                    try await session.updateConfiguration(
                        update,
                        in: .two,
                        accessCode: .set(codeB),
                        currentAccessCode: codeA
                    )
                }
                try await session.putConfiguration(
                    configuration,
                    in: .two,
                    accessCode: .set(codeB),
                    currentAccessCode: codeA
                )
            }
            await context.expectThrows("update with the replaced access code", matching: isAccessDenied) {
                try await session.updateConfiguration(update, in: .two, currentAccessCode: codeA)
            }
            try await session.updateConfiguration(update, in: .two, currentAccessCode: codeB)
            try await verifyHMACSecret(context, transport, session: session)

            if canUpdateCode {
                try await session.updateConfiguration(update, in: .two, accessCode: .remove, currentAccessCode: codeB)
            } else {
                try await session.putConfiguration(
                    configuration,
                    in: .two,
                    accessCode: .remove,
                    currentAccessCode: codeB
                )
            }
            try await session.updateConfiguration(update, in: .two)
            try await verifyHMACSecret(context, transport, session: session)
            try await session.deleteConfiguration(in: .two)
        }
    }

    // MARK: - Helpers

    private static func usesUSBCCID(_ context: Scenario.Context, _ transport: OTPTransport) async throws -> Bool {
        guard transport.kind == .smartCard, context.deviceTransport == .usb else { return false }
        #if os(iOS)
        return try await context.smartCardConnection().lightningConnection == nil
        #else
        return true
        #endif
    }

    // Skips transports that cannot reach the OTP application, and legacy NFC firmware when the
    // scenario depends on the reported slot state.
    private static func skipUnsupportedTransport(
        _ context: Scenario.Context,
        _ transport: OTPTransport,
        needsSlotState: Bool = true
    ) async throws {
        let version = try await context.provider.deviceInfo().version
        if try await usesUSBCCID(context, transport),
            version >= Version("4.0.0")!, version < Version("5.3.0")!
        {
            try context.skip("OTP over USB CCID needs firmware < 4.0 or >= 5.3, device is \(version)")
        }
        if needsSlotState, context.deviceTransport == .nfc,
            version >= Version("5.0.0")!, version < Version("5.2.5")!
        {
            try context.skip("NFC firmware 5.0–5.2.4 cannot report reliable OTP slot state")
        }
    }

    // Opens a session with the given slots cleared, and clears them again in teardown.
    private static func programmableSession(
        _ context: Scenario.Context,
        _ transport: OTPTransport,
        clearing slots: [YubiOTP.Slot] = YubiOTP.Slot.allCases
    ) async throws -> YubiOTP.Session {
        try await skipUnsupportedTransport(context, transport)

        let session = try await context.otpSession(over: transport.kind)
        await context.addTeardown {
            // A fresh session reads the actual slot state, even after a failed write.
            let cleanup = try await context.otpSession(over: transport.kind)
            for slot in slots where try await cleanup.configState.isConfigured(slot) {
                try await cleanup.deleteConfiguration(in: slot)
            }
        }
        for slot in slots where try await session.configState.isConfigured(slot) {
            try await session.deleteConfiguration(in: slot)
        }
        return session
    }

    // Checks that slot 2 still holds `hmacKey`. USB CCID cannot calculate, so it uses OTP HID.
    private static func verifyHMACSecret(
        _ context: Scenario.Context,
        _ transport: OTPTransport,
        session: YubiOTP.Session
    ) async throws {
        var session = session
        if try await usesUSBCCID(context, transport) {
            guard context.provider.capabilities.hasOTP else {
                context.log("USB CCID only: the HMAC secret is not verified")
                return
            }
            session = try await context.otpSession(over: .otpHID)
        }
        let response = try await session.calculateHMACSHA1(challenge: hmacChallenge, in: .two).value
        context.expectEqual(response.hexString, hmacResponse, "the HMAC secret should survive the change")
    }

    // Over OTP HID a refused write is not acknowledged; over CCID it fails with a status word.
    private static func isAccessDenied(_ error: any Error) -> Bool {
        switch error as? YubiOTP.SessionError {
        case .commandRejected:
            return true
        case .failedResponse(let response, _):
            return response.status == .securityConditionNotSatisfied || response.status == .conditionsNotSatisfied
        default:
            return false
        }
    }
}

private struct OTPTransport: ScenarioParameter {

    let kind: Scenario.Context.OTPTransportKind
    let slot: YubiOTP.Slot?
    let minVersion: Version?

    static var allCases: [OTPTransport] { allCases() }

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

    var displayName: String {
        let transport = kind == .otpHID ? "keyboard HID" : "smart card"
        guard let slot else { return transport }
        return "\(transport), slot \(slot.rawValue)"
    }

    var requirements: Requirements {
        Requirements(
            capabilities: [.otp],
            minVersion: minVersion,
            requiresOTPTransport: kind == .otpHID
        )
    }
}

// RFC 2202 HMAC-SHA1 test case 1.
private let hmacKey = Data(repeating: 0x0B, count: 20)
private let hmacChallenge = Data("Hi There".utf8)
private let hmacResponse = "b617318655057264e28bc0b6fb378c8ef146be00"
