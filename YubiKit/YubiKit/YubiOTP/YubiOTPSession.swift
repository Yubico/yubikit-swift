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

// Slot command codes (yubikit.yubiotp CONFIG_SLOT).
private let slotDeviceSerial: UInt8 = 0x10

// The status struct is version[3] ‖ pgmSeq[1] ‖ configState[2, LE].
private let statusConfigStateRange = 4..<6

extension YubiOTP {

    /// A session with the Yubico OTP application on the YubiKey.
    ///
    /// The application is reachable two ways, and this session speaks both: over the OTP keyboard
    /// HID interface (``OTPConnection``, macOS only) and over SmartCard (``SmartCardConnection``,
    /// including NFC). Behaviour is identical whichever transport drives it.
    public final actor Session {

        public typealias Error = YubiOTPSessionError

        let interface: Interface

        /// The firmware version of the Yubico OTP application, typically the YubiKey's firmware
        /// version.
        public let version: Version

        /// The configuration state of the two OTP slots, as of the last command.
        public internal(set) var configState: ConfigState

        private init(interface: Interface) async {
            self.interface = interface
            self.version = await interface.version
            self.configState = ConfigState(flags: await interface.configStateFlags)
        }

        /// Determines whether the session supports the specified feature.
        public func supports(_ feature: Feature) async -> Bool {
            feature.isSupported(by: version)
        }

        /// Creates a new Yubico OTP session over the OTP keyboard HID interface.
        ///
        /// - Parameter connection: The OTP connection to use for this session.
        /// - Throws: ``YubiOTPSessionError`` if session creation fails.
        public static func makeSession(
            connection: OTPConnection
        ) async throws(YubiOTPSessionError) -> Session {
            let otpInterface = try await OTPInterface<Error>(connection: connection)
            return await Session(interface: Interface(interface: otpInterface))
        }

        /// Creates a new Yubico OTP session over a SmartCard connection.
        ///
        /// - Parameters:
        ///   - connection: The SmartCard connection to use for this session.
        ///   - scpKeyParams: Optional SCP key parameters for authenticated communication.
        /// - Throws: ``YubiOTPSessionError`` if the OTP application cannot be selected.
        public static func makeSession(
            connection: SmartCardConnection,
            scpKeyParams: SCPKeyParams? = nil
        ) async throws(YubiOTPSessionError) -> Session {
            let smartCardInterface = try await SmartCardInterface<Error>(
                connection: connection,
                application: .otp,
                keyParams: scpKeyParams
            )
            return await Session(interface: Interface(interface: smartCardInterface))
        }

        /// Reads the YubiKey's serial number.
        ///
        /// - Returns: The serial number, or throws if the key is configured not to expose it.
        public func getSerialNumber() async throws(YubiOTPSessionError) -> UInt {
            let data = try await interface.readData(slot: slotDeviceSerial, expectedLength: 4)
            return data.reduce(UInt(0)) { $0 << 8 | UInt($1) }
        }
    }
}

// MARK: - Interface (Internal Transport Abstraction)

extension YubiOTP.Session {

    /// Abstracts over the underlying transport, so `YubiOTP.Session` can stay a concrete type.
    ///
    /// Mirrors `Management.Session.Interface`. The OTP-specific state — the latest status struct —
    /// lives here rather than in the shared `SmartCardInterface`.
    internal actor Interface {

        private enum Kind {
            case otp(OTPInterface<YubiOTPSessionError>)
            case smartCard(SmartCardInterface<YubiOTPSessionError>)
        }

        private let kind: Kind
        private var status: Data
        private var programmingSequence: UInt8

        init(interface: OTPInterface<YubiOTPSessionError>) async {
            self.kind = .otp(interface)
            let status = await interface.status
            self.status = status
            self.programmingSequence = Array(status).count > 3 ? Array(status)[3] : 0
        }

        init(interface: SmartCardInterface<YubiOTPSessionError>) {
            self.kind = .smartCard(interface)
            // Selecting the OTP application returns the status struct.
            let status = interface.selectResponse
            self.status = status
            self.programmingSequence = Array(status).count > 3 ? Array(status)[3] : 0
        }

        var version: Version {
            get async {
                switch kind {
                case let .otp(interface):
                    return await interface.version
                case .smartCard:
                    return Version(withData: status.prefix(3)) ?? Version(withData: Data([0, 0, 0]))!
                }
            }
        }

        var configStateFlags: UInt16 {
            guard status.count >= statusConfigStateRange.upperBound else { return 0 }
            let bytes = Array(status[statusConfigStateRange.relative(to: status)])
            return UInt16(bytes[0]) | UInt16(bytes[1]) << 8
        }

        /// Runs a configuration write, returning the updated status struct.
        ///
        /// The two transports detect success differently: the OTP frame protocol watches the
        /// programming sequence itself, while over CCID the host has to compare it across the
        /// exchange (`_YubiOtpSmartCardBackend.write_update`).
        func writeConfig(command: UInt8, data: Data) async throws(YubiOTPSessionError) -> Data {
            switch kind {
            case let .otp(interface):
                let status = try await interface.sendAndReceive(slot: command, data: data)
                self.status = status
                programmingSequence = Array(status).count > 3 ? Array(status)[3] : programmingSequence
                return status

            case let .smartCard(interface):
                var status: Data = try await interface.send(
                    apdu: APDU(cla: 0, ins: 0x01, p1: command, p2: 0, command: data)
                )
                if status.isEmpty {
                    // Some YubiKeys answer certain commands with no data; ask for the status.
                    status = try await interface.send(apdu: APDU(cla: 0, ins: 0x03, p1: 0, p2: 0))
                }
                let bytes = Array(status)
                guard bytes.count >= 5 else {
                    throw .responseParseError("Truncated OTP status struct", source: .here())
                }

                let previous = programmingSequence
                programmingSequence = bytes[3]
                self.status = status

                if programmingSequence == previous &+ 1 { return status }
                if programmingSequence == 0, previous > 0 {
                    // Deleting the last configuration resets the sequence to zero.
                    if bytes[4] & 0x1F == 0 { return status }
                    // These firmware revisions simply do not advance the programming state.
                    if let version = Version(withData: status.prefix(3)),
                        version >= Version("5.0.0")!, version < Version("5.4.3")!
                    {
                        return status
                    }
                }
                throw .commandRejected("The configuration was not updated", source: .here())
            }
        }

        /// Cancels an in-flight touch-triggered read.
        ///
        /// Only the OTP transport can be interrupted; over SmartCard the exchange is a single
        /// blocking APDU, exactly as in `_YubiOtpSmartCardBackend.send_and_receive`.
        func cancel() async {
            if case let .otp(interface) = kind {
                await interface.cancel()
            }
        }

        /// Runs a slot command that reads data, validating the transport's integrity check.
        func readData(
            slot: UInt8,
            data: Data = Data(),
            expectedLength: Int,
            onKeepalive: (@Sendable (UInt8) -> Void)? = nil
        ) async throws(YubiOTPSessionError) -> Data {
            switch kind {
            case let .otp(interface):
                // The OTP transport returns the payload followed by its CRC trailer.
                let response = try await interface.sendAndReceive(
                    slot: slot,
                    data: data,
                    onKeepalive: onKeepalive
                )
                guard response.count >= expectedLength + 2,
                    response.prefix(expectedLength + 2).hasValidCRC16
                else {
                    throw .responseParseError("Invalid CRC in OTP data response", source: .here())
                }
                return response.prefix(expectedLength)

            case let .smartCard(interface):
                // CCID checks integrity itself, so the applet returns exactly the payload.
                let apdu = APDU(cla: 0, ins: 0x01, p1: slot, p2: 0, command: data)
                let response: Data = try await interface.send(apdu: apdu)
                guard response.count == expectedLength else {
                    throw .responseParseError(
                        "Expected \(expectedLength) bytes from the OTP application, got \(response.count)",
                        source: .here()
                    )
                }
                return response
            }
        }
    }
}
