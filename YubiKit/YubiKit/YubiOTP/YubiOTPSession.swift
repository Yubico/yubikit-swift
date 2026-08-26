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

// The status struct layout is shared with the transport conformances in `YubiOTPInterface.swift`.

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
    /// Mirrors `Management.Session.Interface`. Neither transport keeps protocol state here: the
    /// cached status struct exists only to back ``Session/configState``.
    internal actor Interface {

        private enum Kind {
            case otp(OTPInterface<YubiOTPSessionError>)
            case smartCard(SmartCardInterface<YubiOTPSessionError>)
        }

        private let kind: Kind

        /// The most recent status struct, stored as an array so its indices are always zero-based
        /// whatever slice the transport handed back.
        private var status: [UInt8]

        init(interface: OTPInterface<YubiOTPSessionError>) async {
            self.kind = .otp(interface)
            self.status = await interface.initialStatus
        }

        init(interface: SmartCardInterface<YubiOTPSessionError>) async {
            self.kind = .smartCard(interface)
            self.status = await interface.initialStatus
        }

        var version: Version {
            get async {
                switch kind {
                case let .otp(interface): return await interface.version
                case let .smartCard(interface): return await interface.version
                }
            }
        }

        var configStateFlags: UInt16 {
            guard status.count > statusOffsetConfigState + 1 else { return 0 }
            return UInt16(status[statusOffsetConfigState]) | UInt16(status[statusOffsetConfigState + 1]) << 8
        }

        /// Runs a configuration write, caching the status struct it returns.
        func writeConfig(command: UInt8, data: Data) async throws(YubiOTPSessionError) {
            switch kind {
            case let .otp(interface):
                status = try await interface.writeConfig(command: command, data: data)
            case let .smartCard(interface):
                status = try await interface.writeConfig(command: command, data: data)
            }
        }

        func cancel() async {
            switch kind {
            case let .otp(interface): await interface.cancel()
            case let .smartCard(interface): await interface.cancel()
            }
        }

        func readData(
            slot: UInt8,
            data: Data = Data(),
            expectedLength: Int,
            onKeepalive: (@Sendable (UInt8) -> Void)? = nil
        ) async throws(YubiOTPSessionError) -> Data {
            switch kind {
            case let .otp(interface):
                return try await interface.readData(
                    slot: slot,
                    data: data,
                    expectedLength: expectedLength,
                    onKeepalive: onKeepalive
                )
            case let .smartCard(interface):
                return try await interface.readData(
                    slot: slot,
                    data: data,
                    expectedLength: expectedLength,
                    onKeepalive: onKeepalive
                )
            }
        }
    }
}
