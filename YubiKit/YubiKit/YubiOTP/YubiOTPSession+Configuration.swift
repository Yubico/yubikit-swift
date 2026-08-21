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

private let slotSwap: UInt8 = 0x06
private let slotScanMap: UInt8 = 0x12

private let hmacChallengeSize = 64
private let hmacResponseSize = 20

extension YubiOTP.Session {

    // MARK: - Programming

    /// Writes a configuration to a slot, replacing whatever was there.
    ///
    /// - Parameters:
    ///   - configuration: The slot configuration to write.
    ///   - slot: The slot to program.
    ///   - accessCode: A new access code to protect the slot with.
    ///   - currentAccessCode: The slot's existing access code, if it is protected.
    public func putConfiguration(
        _ configuration: YubiOTP.SlotConfiguration,
        in slot: YubiOTP.Slot,
        accessCode: Data? = nil,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTPSessionError) {
        guard configuration.isSupported(by: version) else {
            throw .featureNotSupported(source: .here())
        }
        guard let configuration = configuration as? SlotConfigurationInternal else {
            throw .illegalArgument("Unsupported slot configuration type", source: .here())
        }
        try await write(
            command: slot.configCommand,
            config: configuration.configData(accessCode: accessCode),
            currentAccessCode: currentAccessCode
        )
    }

    /// Updates the flags of an already-programmed slot, preserving its secret.
    ///
    /// > Note: Requires ``YubiOTP/Feature/update``, available on YubiKey 2.3 or later.
    public func updateConfiguration(
        _ configuration: YubiOTP.SlotConfiguration,
        in slot: YubiOTP.Slot,
        accessCode: Data? = nil,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTPSessionError) {
        guard configuration.isSupported(by: version) else {
            throw .featureNotSupported(source: .here())
        }
        // These firmware revisions silently fail to change the access code during an update.
        if accessCode != currentAccessCode,
            version >= Version("4.3.2")!, version < Version("4.3.6")!
        {
            throw .featureNotSupported(source: .here())
        }
        guard let configuration = configuration as? SlotConfigurationInternal else {
            throw .illegalArgument("Unsupported slot configuration type", source: .here())
        }
        try await write(
            command: slot.updateCommand,
            config: configuration.configData(accessCode: accessCode),
            currentAccessCode: currentAccessCode
        )
    }

    /// Deletes the configuration stored in a slot.
    public func deleteConfiguration(
        in slot: YubiOTP.Slot,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTPSessionError) {
        // An all-zero configuration block is how a slot is cleared.
        try await write(
            command: slot.configCommand,
            config: Data(count: otpConfigSize),
            currentAccessCode: currentAccessCode
        )
    }

    /// Swaps the configurations of the two slots.
    ///
    /// > Note: Requires ``YubiOTP/Feature/swap``, available on YubiKey 2.3 or later.
    public func swapConfigurations() async throws(YubiOTPSessionError) {
        guard await supports(.swap) else { throw .featureNotSupported(source: .here()) }
        try await write(command: slotSwap, config: Data(), currentAccessCode: nil)
    }

    /// Replaces the scan-code map the YubiKey uses when typing out its output.
    public func setScanMap(
        _ scanMap: Data,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTPSessionError) {
        try await write(command: slotScanMap, config: scanMap, currentAccessCode: currentAccessCode)
    }

    /// Configures a slot to emit an NDEF record over NFC.
    ///
    /// > Note: Requires ``YubiOTP/Feature/ndef``, available on YubiKey 3.0 or later.
    ///
    /// - Parameters:
    ///   - slot: The slot to configure.
    ///   - uri: The URI or text to emit. Defaults to ``YubiOTP/defaultNDEFURI`` for a URI record.
    ///   - type: Whether to emit a URI or a text record.
    public func setNDEFConfiguration(
        in slot: YubiOTP.Slot,
        uri: String? = nil,
        type: YubiOTP.NDEFType = .uri,
        currentAccessCode: Data? = nil
    ) async throws(YubiOTPSessionError) {
        let config = try YubiOTP.buildNDEFConfig(value: uri, type: type)
        try await write(command: slot.ndefCommand, config: config, currentAccessCode: currentAccessCode)
    }

    // MARK: - Challenge-response

    /// Performs an HMAC-SHA1 challenge-response against a slot.
    ///
    /// If the slot was programmed with `requireTouch`, the YubiKey waits for a button press before
    /// answering. The returned stream reports that wait as
    /// ``YubiOTP/Status/waitingForUser(cancel:)`` so a caller can prompt and offer to give up; when
    /// no such feedback is needed, read ``YubiOTP/StatusStream/value``.
    ///
    /// > Important: A touch-triggered slot only works over the OTP keyboard transport, which polls
    /// the key — the pending touch shows up on every report, and the host can abort between polls.
    /// Over SmartCard the YubiOTP application refuses the command outright with `0x6985` rather than
    /// waiting, so the stream yields ``YubiOTP/Status/finished(_:)`` alone and cancellation does
    /// nothing. Python and Java accept the same parameters on their SmartCard backends and likewise
    /// ignore them.
    /// >
    /// > This is a limitation of the application, not of SmartCard: an application that defines a
    /// continuation on top of APDUs can report progress and be cancelled over the same transport.
    /// CTAP2 does exactly that — it answers `0x9100` and the host polls with `NFCCTAP_GETRESPONSE`,
    /// which is how ``CTAP2/Status/waitingForUser(cancel:)`` works over NFC. YubiOTP defines no such
    /// exchange.
    ///
    /// > Note: Requires ``YubiOTP/Feature/challengeResponse``, available on YubiKey 2.2 or later.
    ///
    /// - Parameters:
    ///   - challenge: The challenge. Padded to 64 bytes before transmission.
    ///   - slot: The slot to challenge.
    /// - Returns: A stream yielding progress and finally the 20-byte HMAC-SHA1 response.
    public func calculateHMACSHA1(
        challenge: Data,
        in slot: YubiOTP.Slot
    ) async -> YubiOTP.StatusStream<Data> {
        guard await supports(.challengeResponse) else {
            return .error(.featureNotSupported(source: .here()))
        }
        guard challenge.count <= hmacChallengeSize else {
            return .error(
                .illegalArgument("Challenge must be at most \(hmacChallengeSize) bytes", source: .here())
            )
        }

        // Pad with a byte that differs from the last one, so the key can strip the padding again.
        let padByte: UInt8 = challenge.last == 0 ? 1 : 0
        let padded = challenge + Data(repeating: padByte, count: hmacChallengeSize - challenge.count)

        let interface = self.interface
        return YubiOTP.StatusStream { continuation in
            Task {
                let cancel: @Sendable () async -> Void = { await interface.cancel() }
                do throws(YubiOTPSessionError) {
                    let response = try await interface.readData(
                        slot: slot.challengeHMACCommand,
                        data: padded,
                        expectedLength: hmacResponseSize,
                        onKeepalive: { code in
                            continuation.yield(
                                code == keepaliveUserPresenceNeeded
                                    ? .waitingForUser(cancel: cancel) : .processing
                            )
                        }
                    )
                    continuation.yield(.finished(response))
                } catch {
                    continuation.yield(error: error)
                }
            }
        }
    }

    // MARK: - Private

    /// Every configuration write carries the slot's *current* access code after the config block.
    private func write(
        command: UInt8,
        config: Data,
        currentAccessCode: Data?
    ) async throws(YubiOTPSessionError) {
        if let currentAccessCode, currentAccessCode.count != otpAccessCodeSize {
            throw .illegalArgument("Access code must be exactly \(otpAccessCodeSize) bytes", source: .here())
        }
        var payload = config
        payload.append(currentAccessCode ?? Data(count: otpAccessCodeSize))
        let status = try await interface.writeConfig(command: command, data: payload)
        configState = YubiOTP.ConfigState(flags: Self.configStateFlags(in: status))
    }

    static func configStateFlags(in status: Data) -> UInt16 {
        let bytes = Array(status)
        guard bytes.count >= 6 else { return 0 }
        return UInt16(bytes[4]) | UInt16(bytes[5]) << 8
    }
}
