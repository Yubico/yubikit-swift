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

import CryptoTokenKit
import Foundation
import YubiKit

/// Connection scenarios.
enum ConnectionScenario: CaseIterable, ScenarioSuite {

    case open
    case closeNotifies
    case serial
    case cancellation
    case sendManually
    case selectWrongApp
    case withDeviceFIDOHID
    case alertMessage
    case closingErrorMessage

    var scenario: Scenario {
        switch self {
        // MARK: - SmartCard (connection lifecycle)
        case .open:
            return Scenario(
                "Connection.SmartCard.open",
                "acquires a usable SmartCard connection (acquisition succeeding is the assertion)"
            ) { context in
                let connection = try await context.smartCardConnection()
                _ = try await Management.Session.makeSession(connection: connection).getDeviceInfo()
                context.log("acquired a usable SmartCard connection: \(connection)")
            }
        case .closeNotifies:
            return Scenario(
                "Connection.SmartCard.closeNotifies",
                "waitUntilClosed() is notified with the closing error"
            ) { context in
                let connection = try await context.smartCardConnection()

                let closureTask = Task { await connection.waitUntilClosed() }
                // Let the task reach its await before we close, so the notification isn't missed.
                try await Task.sleep(for: .seconds(1))

                await connection.close(error: ConnectionTestError())
                let error = await closureTask.value
                context.expect(error is ConnectionTestError, "notified when connection closed with the right error")
            }
        case .serial:
            return Scenario(
                "Connection.SmartCard.serial",
                "a second connection fails until the first is closed",
                requirements: Requirements(transports: [.usb], requiresRealHardware: true)
            ) { context in
                let provider = context.provider

                let firstConnection = try await provider.makeSmartCardConnection()
                context.log("got first connection \(firstConnection)")
                let task = Task { await firstConnection.waitUntilClosed() }

                try? await Task.sleep(for: .seconds(1))
                let new = try? await provider.makeSmartCardConnection()
                context.expect(new == nil, "second connection failed as expected")
                if let new { await new.close(error: nil) }

                await firstConnection.close(error: nil)
                let closingError = await task.value
                context.expect(closingError == nil, "waitUntilClosed() returned: \(String(describing: closingError))")

                try? await Task.sleep(for: .seconds(1))
                let secondConnection = try await provider.makeSmartCardConnection()
                context.log("got second connection \(secondConnection)")
                await secondConnection.close(error: nil)
            }
        case .cancellation:
            return Scenario(
                "Connection.SmartCard.cancellation",
                "concurrent open attempts resolve to a single connection",
                requirements: Requirements(transports: [.usb], requiresRealHardware: true)
            ) { context in
                let provider = context.provider
                let attempts = (0..<4).map { _ in Task { try? await provider.makeSmartCardConnection() } }

                var connections: [any SmartCardConnection] = []
                for attempt in attempts {
                    if let connection = await attempt.value { connections.append(connection) }
                }
                context.expect(connections.count == 1, "exactly one concurrent connection should succeed")

                for connection in connections { await connection.close(error: nil) }
            }
        // MARK: - Raw APDU
        case .sendManually:
            return Scenario(
                "Connection.RawAPDU.sendManually",
                "manual SELECT + device-info exchange reads the firmware version"
            ) { context in
                let connection = try await context.smartCardConnection()

                let managementAID: [UInt8] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17]
                let selectResponse = try await connection.send(data: selectAPDU(aid: managementAID))
                context.expect(responseStatus(selectResponse) == .ok, "SELECT Management should return 0x9000")

                let deviceInfoAPDU = Data([0x00, 0x1D, 0x00, 0x00])
                let deviceInfoResponse = try await connection.send(data: deviceInfoAPDU)
                context.expect(responseStatus(deviceInfoResponse) == .ok, "device-info command should return 0x9000")

                // The device-info payload is `<total-length> <BER-TLV records...>`; skip the leading length.
                let payload = responsePayload(deviceInfoResponse)
                let records = TKBERTLVRecord.sequenceOfRecords(from: Data(payload.dropFirst()))
                let versionData = try context.require(
                    records?.first(where: { $0.tag == 0x05 })?.value,
                    "no YubiKey version record (tag 0x05) in the device-info result"
                )
                try context.require(
                    versionData.count == 3,
                    "version record should be 3 bytes, got \(versionData.hexString)"
                )
                let bytes = [UInt8](versionData)
                context.log("got version: \(bytes[0]).\(bytes[1]).\(bytes[2])")
                context.expect(bytes[0] == 5, "expected a YubiKey 5 series device, got major \(bytes[0])")

                // Selecting a non-existent AID must report not-found rather than succeed.
                let notFoundResponse = try await connection.send(data: selectAPDU(aid: [0x01, 0x02, 0x03]))
                let notFoundStatus = responseStatus(notFoundResponse)
                context.expect(
                    notFoundStatus == .fileNotFound
                        || notFoundStatus == .incorrectParameters
                        || notFoundStatus == .invalidInstruction,
                    "unexpected status selecting a non-existent applet: \(notFoundStatus)"
                )
            }
        case .selectWrongApp:
            return Scenario(
                "Connection.RawAPDU.selectWrongApp",
                "selecting a non-existent applet reports application-not-available"
            ) { context in
                let connection = try await context.smartCardConnection()
                let status = responseStatus(try await connection.send(data: selectAPDU(aid: [0x01, 0x02, 0x03])))
                context.expect(
                    status == .fileNotFound
                        || status == .incorrectParameters
                        || status == .invalidInstruction,
                    "unexpected status selecting a non-existent applet: \(status)"
                )
            }
        // MARK: - FIDO HID
        case .withDeviceFIDOHID:
            return Scenario(
                "Connection.FIDOHID.withDevice",
                "opens a FIDO HID connection to an attached device",
                requirements: Requirements(requiresFIDOTransport: true)
            ) { context in
                let connection = try await context.provider.makeFIDOConnection()
                context.expect(connection.mtu == 64, "FIDO HID packet MTU should be 64 bytes")
                await connection.close(error: nil)
            }
        // MARK: - NFC (iOS reader-UI, transport-gated)
        case .alertMessage:
            return Scenario(
                "Connection.NFC.alertMessage",
                "the NFC reader alert message can be updated and the session closed with a message",
                requirements: Requirements(transports: [.nfc]),
                platform: .iOS
            ) { context in
                #if os(iOS)
                let connection = try await context.smartCardConnection()
                let nfc = try context.require(connection.nfcConnection, "expected an NFC connection")
                await nfc.setAlertMessage("Updated Alert Message")
                try? await Task.sleep(for: .seconds(1))
                await nfc.close(message: "Closing Alert Message")
                context.log("NFC alert message updated and session closed with a message")
                #else
                try context.skip("NFC scenarios are iOS-only")
                #endif
            }
        case .closingErrorMessage:
            return Scenario(
                "Connection.NFC.closingErrorMessage",
                "an NFC connection closes cleanly",
                requirements: Requirements(transports: [.nfc]),
                platform: .iOS
            ) { context in
                #if os(iOS)
                let connection = try await context.smartCardConnection()
                try context.require(connection.nfcConnection != nil, "expected an NFC connection")
                await connection.close(error: nil)
                context.log("NFC connection closed")
                #else
                try context.skip("NFC scenarios are iOS-only")
                #endif
            }
        }
    }
}

// MARK: - Suite-private helpers

private struct ConnectionTestError: Error {}

private func selectAPDU(aid: [UInt8]) -> Data {
    Data([0x00, 0xA4, 0x04, 0x00, UInt8(aid.count)] + aid)
}

private func responseStatus(_ response: Data) -> Response.Status.Code {
    guard response.count >= 2 else { return .unknown }
    let tail = Array(response.suffix(2))
    let sw = (UInt16(tail[0]) << 8) | UInt16(tail[1])
    return Response.Status.Code(rawValue: sw) ?? .unknown
}

private func responsePayload(_ response: Data) -> Data {
    guard response.count >= 2 else { return Data() }
    return Data(response.prefix(response.count - 2))
}
