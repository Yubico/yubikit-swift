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
import Logging

extension YubiOTP {

    /// A session with the Yubico OTP application on the YubiKey.
    ///
    /// Create the session over the OTP keyboard HID interface (``OTPConnection``) or over a
    /// ``SmartCardConnection``. The available operations depend on the firmware and the transport.
    public final actor Session: YubiKit.Session {

        /// The error type thrown by Yubico OTP session operations.
        public typealias Error = YubiOTP.SessionError

        /// The firmware version of the Yubico OTP application, typically the YubiKey's firmware
        /// version.
        public let version: Version

        /// The configuration state of the two OTP slots, as of the last command.
        ///
        /// Over NFC on firmware 5.0.0 through 5.2.4, both slots are reported as configured
        /// because those versions cannot report reliable slot state.
        public internal(set) var configState: ConfigState

        /// Determines whether the session supports the specified feature.
        public func supports(_ feature: Feature) async -> Bool {
            feature.isSupported(by: version)
        }

        /// Creates a new Yubico OTP session over the OTP keyboard HID interface.
        ///
        /// - Parameter connection: The OTP connection to use for this session.
        /// - Throws: ``YubiOTP/SessionError`` if session creation fails.
        public static func makeSession(
            connection: OTPConnection
        ) async throws(YubiOTP.SessionError) -> Session {
            let otpInterface = try await OTPKeyboardInterface(connection: connection)
            if otpInterface.version.major == 3 {
                // The YubiKey NEO can cache a stale programming sequence. An invalid scan map
                // makes it refresh the cache; the key rejects the scan map itself.
                logger.debug("Refreshing NEO OTP programming sequence")
                do {
                    _ = try await otpInterface.sendAndReceive(slot: YubiOTP.scanMapCommand, data: neoRefreshScanMap)
                } catch .commandRejected {
                }
                _ = try await otpInterface.readStatus()
            }
            return await Session(interface: Interface(interface: otpInterface), transport: "OTP")
        }

        /// Creates a new Yubico OTP session over a SmartCard connection.
        ///
        /// - Parameters:
        ///   - connection: The SmartCard connection to use for this session.
        ///   - scpKeyParams: Optional SCP key parameters for authenticated communication.
        /// - Throws: ``YubiOTP/SessionError`` if session creation fails.
        public static func makeSession(
            connection: SmartCardConnection,
            scpKeyParams: SCPKeyParams? = nil
        ) async throws(YubiOTP.SessionError) -> Session {
            #if os(iOS)
            let isNFC = connection.nfcConnection != nil
            #else
            let isNFC = false
            #endif
            return try await makeSession(connection: connection, scpKeyParams: scpKeyParams, isNFC: isNFC)
        }

        /// Reads the serial number of the YubiKey.
        ///
        /// - Throws: ``YubiOTP/SessionError`` if the YubiKey does not expose its serial number, as
        ///   controlled by ``YubiOTP/SlotOptions/serialAPIVisible``.
        public func getSerialNumber() async throws(YubiOTP.SessionError) -> UInt {
            logger.debug("Reading serial number")
            let data = try await interface.readData(slot: YubiOTP.deviceSerialCommand, expectedLength: 4)
            return data.reduce(UInt(0)) { $0 << 8 | UInt($1) }
        }

        /// Calculates the HMAC-SHA1 response to a challenge with the secret of a slot.
        ///
        /// A slot programmed with `requireTouch` waits for a touch of the YubiKey. The stream reports
        /// the wait as ``YubiOTP/Status/waitingForUser(cancel:)``. Read ``YubiOTP/StatusStream/value``
        /// when you do not need this feedback.
        ///
        /// > Important: Only the OTP keyboard transport can wait for a touch. Over NFC, the YubiKey
        /// > rejects a slot that requires touch. USB and Lightning SmartCard do not support challenge-response.
        ///
        /// > Note: Requires ``YubiOTP/Feature/challengeResponse``, available on YubiKey 2.2 or later.
        ///
        /// - Parameters:
        ///   - challenge: The challenge, at most 64 bytes.
        ///   - slot: The slot that holds the HMAC-SHA1 secret.
        /// - Returns: A stream that finishes with the 20-byte response.
        public func calculateHMACSHA1(
            challenge: Data,
            in slot: YubiOTP.Slot
        ) async -> YubiOTP.StatusStream<Data> {
            guard await supports(.challengeResponse) else {
                return .error(.featureNotSupported(source: .here()))
            }
            guard challenge.count <= hmacChallengeSize else {
                return .error(.illegalArgument("Challenge must be at most \(hmacChallengeSize) bytes", source: .here()))
            }
            logger.debug("Calculating HMAC-SHA1 response", metadata: ["slot": .stringConvertible(slot.rawValue)])

            // Pad with a byte that differs from the last one, so the key can strip the padding.
            let padByte: UInt8 = challenge.last == 0 ? 1 : 0
            let padded = challenge + Data(repeating: padByte, count: hmacChallengeSize - challenge.count)

            let interface = self.interface
            let operationID = UUID()
            return YubiOTP.StatusStream { continuation in
                Task {
                    let cancel: @Sendable () async -> Void = { await interface.cancel(operationID: operationID) }
                    do throws(YubiOTP.SessionError) {
                        let response = try await interface.readData(
                            slot: slot.challengeHMACCommand,
                            data: padded,
                            expectedLength: hmacResponseSize,
                            operationID: operationID,
                            onKeepalive: { waitingForTouch in
                                continuation.yield(waitingForTouch ? .waitingForUser(cancel: cancel) : .processing)
                            }
                        )
                        continuation.yield(.finished(response))
                    } catch {
                        continuation.yield(error: error)
                    }
                }
            }
        }

        // MARK: - Internal

        let interface: Interface

        static func makeSession(
            connection: SmartCardConnection,
            scpKeyParams: SCPKeyParams? = nil,
            isNFC: Bool
        ) async throws(YubiOTP.SessionError) -> Session {
            // Over NFC, the Management application reports the firmware version more reliably.
            var managementVersion: Version?
            if isNFC {
                do throws(YubiOTP.SessionError) {
                    let management = try await SmartCardInterface<Error>(
                        connection: connection,
                        application: .management
                    )
                    guard let version = Version(withManagementResult: management.selectResponse) else {
                        throw .responseParseError("Invalid Management firmware version", source: .here())
                    }
                    managementVersion = version
                } catch .featureNotSupported {
                    // Older keys may not expose Management over NFC.
                }
            }
            let smartCardInterface = try await SmartCardInterface<Error>(
                connection: connection,
                application: .otp,
                keyParams: scpKeyParams
            )
            let interface = try Interface(
                interface: smartCardInterface,
                managementVersion: managementVersion,
                isNFC: isNFC
            )
            return await Session(interface: interface, transport: "SmartCard")
        }

        // MARK: - Private

        private init(interface: Interface, transport: String) async {
            self.interface = interface
            self.version = interface.version
            self.configState = ConfigState(version: version, flags: await interface.configStateFlags)
            logger.debug(
                "YubiOTP session initialized",
                metadata: [
                    "transport": .string(transport),
                    "version": .stringConvertible(version),
                    "state": .stringConvertible(configState),
                ]
            )
        }
    }
}

extension YubiOTP.Session: HasOTPLogger {}

private let hmacChallengeSize = 64
private let hmacResponseSize = 20

// 51 bytes of "c": an invalid scan map.
private let neoRefreshScanMap = Data(repeating: 0x63, count: 51)
