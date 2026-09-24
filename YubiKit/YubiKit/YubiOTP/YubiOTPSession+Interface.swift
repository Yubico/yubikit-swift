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

// MARK: - Interface (Internal Transport Abstraction)

extension YubiOTP.Session {

    /// Internal actor that abstracts over the OTP keyboard and SmartCard transports.
    ///
    /// It runs one command at a time, so that no command can interleave with a challenge that
    /// waits for touch.
    internal actor Interface {

        let version: Version

        // Only the OTP keyboard transport and NFC can calculate an HMAC-SHA1 response.
        let supportsChallengeResponse: Bool

        // The low byte of the configuration state; the high byte holds only the touch level.
        var configStateFlags: UInt8 { status[statusOffsetConfigState] }

        init(interface: OTPKeyboardInterface) async {
            self.kind = .otp(interface)
            self.version = interface.version
            self.supportsChallengeResponse = true
            self.status = Array(await interface.status)
            self.usesDummyStatus = false
        }

        init(
            interface: SmartCardInterface<YubiOTP.SessionError>,
            managementVersion: Version?,
            isNFC: Bool
        ) throws(YubiOTP.SessionError) {
            let status = Array(interface.selectResponse)
            guard status.count >= otpStatusSize else {
                throw .responseParseError("Truncated OTP status struct", source: .here())
            }
            let otpVersion = Version(withData: Data(status.prefix(3)))!
            // The YubiKey NEO reports the higher of the two versions.
            let version = managementVersion.map { $0.major == 3 ? max($0, otpVersion) : $0 } ?? otpVersion
            // These firmware versions cannot report reliable slot state over NFC.
            let usesDummyStatus = isNFC && version >= Version("5.0.0")! && version < Version("5.2.5")!

            self.kind = .smartCard(interface)
            self.version = version
            self.supportsChallengeResponse = isNFC
            self.usesDummyStatus = usesDummyStatus
            self.status = usesDummyStatus ? Array(status.prefix(4)) + dummyConfigState : status
        }

        func writeConfig(command: UInt8, data: Data) async throws(YubiOTP.SessionError) {
            try await acquireOperation()
            defer { releaseOperation() }
            switch kind {
            case let .otp(interface):
                status = Array(try await interface.sendAndReceive(slot: command, data: data))
            case let .smartCard(interface) where usesDummyStatus:
                let _: Data = try await interface.send(
                    apdu: APDU(cla: 0, ins: insConfig, p1: command, p2: 0, command: data)
                )
            case let .smartCard(interface):
                let previous = status[statusOffsetProgrammingSequence]
                status = try await interface.writeConfig(command: command, data: data)
                guard isWriteAcknowledged(previousProgrammingSequence: previous) else {
                    throw .commandRejected("The configuration was not updated", source: .here())
                }
            }
        }

        func readData(
            slot: UInt8,
            data: Data = Data(),
            expectedLength: Int,
            operationID: UUID? = nil,
            onKeepalive: (@Sendable (_ waitingForTouch: Bool) -> Void)? = nil
        ) async throws(YubiOTP.SessionError) -> Data {
            try await acquireOperation()
            defer { releaseOperation() }
            switch kind {
            case let .otp(interface):
                let response = try await interface.sendAndReceive(
                    slot: slot,
                    data: data,
                    operationID: operationID,
                    onKeepalive: onKeepalive
                )
                guard response.count >= expectedLength + 2, response.prefix(expectedLength + 2).hasValidCRC16 else {
                    throw .responseParseError("Invalid CRC in OTP data response", source: .here())
                }
                return response.prefix(expectedLength)
            case let .smartCard(interface):
                // A single blocking APDU: there is no progress to report.
                let response: Data = try await interface.send(
                    apdu: APDU(cla: 0, ins: insConfig, p1: slot, p2: 0, command: data)
                )
                guard response.count == expectedLength else {
                    throw .responseParseError(
                        "Expected \(expectedLength) bytes from the OTP application, got \(response.count)",
                        source: .here()
                    )
                }
                return response
            }
        }

        // Only the OTP keyboard transport polls the key, so only it can abandon a command.
        func cancel(operationID: UUID) async {
            guard case let .otp(interface) = kind else { return }
            await interface.cancel(operationID: operationID)
        }

        // MARK: - Private

        private enum Kind {
            case otp(OTPKeyboardInterface)
            case smartCard(SmartCardInterface<YubiOTP.SessionError>)
        }

        private struct OperationWaiter {
            let id: UUID
            let continuation: CheckedContinuation<Bool, Never>
        }

        private let kind: Kind
        private let usesDummyStatus: Bool
        // A copy of the status struct, so that slices from either transport have zero-based indices.
        private var status: [UInt8]
        private var operationInFlight = false
        private var operationWaiters: [OperationWaiter] = []

        // A write advances the programming sequence. The sequence resets to zero when the last
        // configuration is deleted, and some firmware versions do not advance it over SmartCard.
        private func isWriteAcknowledged(previousProgrammingSequence previous: UInt8) -> Bool {
            let current = status[statusOffsetProgrammingSequence]
            if current == previous &+ 1 { return true }
            guard current == 0, previous > 0 else { return false }
            let version = Version(withData: Data(status.prefix(3)))!
            return status[statusOffsetConfigState] & configStateMask == 0
                || (version >= Version("5.0.0")! && version < Version("5.4.3")!)
        }

        private func acquireOperation() async throws(YubiOTP.SessionError) {
            guard !Task.isCancelled else { throw .cancelled(source: .here()) }
            guard operationInFlight else {
                operationInFlight = true
                return
            }
            let id = UUID()
            let acquired = await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    if Task.isCancelled {
                        continuation.resume(returning: false)
                    } else {
                        operationWaiters.append(OperationWaiter(id: id, continuation: continuation))
                    }
                }
            } onCancel: {
                Task { await self.cancelWaiter(id: id) }
            }
            guard acquired else { throw .cancelled(source: .here()) }
            if Task.isCancelled {
                releaseOperation()
                throw .cancelled(source: .here())
            }
        }

        private func cancelWaiter(id: UUID) {
            guard let index = operationWaiters.firstIndex(where: { $0.id == id }) else { return }
            operationWaiters.remove(at: index).continuation.resume(returning: false)
        }

        private func releaseOperation() {
            guard !operationWaiters.isEmpty else {
                operationInFlight = false
                return
            }
            operationWaiters.removeFirst().continuation.resume(returning: true)
        }
    }
}

// MARK: - SmartCard transport

extension SmartCardInterface where Error == YubiOTP.SessionError {

    // Writes a configuration and returns the status struct that follows it.
    fileprivate func writeConfig(command: UInt8, data: Data) async throws(Error) -> [UInt8] {
        var response: Data = try await send(apdu: APDU(cla: 0, ins: insConfig, p1: command, p2: 0, command: data))
        if response.isEmpty {
            // Some YubiKeys return no status for some commands.
            response = try await send(apdu: APDU(cla: 0, ins: insStatus, p1: 0, p2: 0))
        }
        guard response.count >= otpStatusSize else {
            throw .responseParseError("Truncated OTP status struct", source: .here())
        }
        return Array(response)
    }
}

// CCID instruction bytes.
private let insConfig: UInt8 = 0x01
private let insStatus: UInt8 = 0x03

// Both slots configured: the status that firmware without reliable NFC slot state reports.
private let dummyConfigState: [UInt8] = [0x03, 0x00]
