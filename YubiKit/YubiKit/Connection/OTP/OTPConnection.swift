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

// The Yubico OTP protocol moves all traffic in fixed 8-byte feature reports: seven payload bytes
// followed by a sequence/status byte. Unlike FIDO's MTU this is not device-dependent, so the
// protocol supplies it rather than each connection declaring its own.
let otpFeatureReportSize = 8

/// A low-level transport connection to the Yubico OTP application on a YubiKey.
///
/// Use an OTP connection to exchange 8-byte HID feature reports with the YubiKey's keyboard
/// interface. Higher-level framing — the 70-byte command frame, CRC, and programming-sequence
/// tracking — is handled above this layer; a connection only moves whole reports.
///
/// > Note: This is the keyboard HID interface (usage page `0x01`, usage `0x06`), not the FIDO HID
/// interface used by ``FIDOConnection``. A YubiKey only exposes it when the Yubico OTP application
/// is enabled over USB.
public protocol OTPConnection: Connection {

    /// Create a new OTPConnection to the YubiKey.
    ///
    /// The init method will wait until a connection to a YubiKey has been established.
    ///
    /// The init will throw with ``OTPConnectionError/busy`` if there is an already established
    /// connection for the same resource.
    init() async throws(OTPConnectionError)

    /// Send one 8-byte feature report.
    ///
    /// - Parameter report: The report to send. Must be exactly ``reportSize`` bytes.
    /// - Throws: ``OTPConnectionError`` if transmission fails.
    func send(_ report: Data) async throws(OTPConnectionError)

    /// Receive one 8-byte feature report.
    ///
    /// - Returns: The received report, exactly ``reportSize`` bytes.
    /// - Throws: ``OTPConnectionError`` if reception fails.
    func receive() async throws(OTPConnectionError) -> Data

    /// Create a new OTPConnection to the YubiKey.
    ///
    /// Call this method to get a connection to a YubiKey. The method will wait until a connection
    /// to a YubiKey has been established and then return it.
    ///
    /// > Warning: Only one connection can exist at a time per device. If this method is called
    /// while another connection is active or pending to the same device, it will throw
    /// ``OTPConnectionError/busy``. The existing connection must be closed first using
    /// ``close(error:)``.
    static func makeConnection() async throws(OTPConnectionError) -> Self

    /// Close the current connection.
    ///
    /// - Parameter error: Optional error that caused the connection to close.
    func close(error: Error?) async

    /// Wait for the connection to close.
    ///
    /// - Returns: An error if the connection was closed due to an error, or `nil` if closed
    ///   normally.
    func waitUntilClosed() async -> Error?

}

extension OTPConnection {

    /// The size of a feature report, in bytes. Always 8 for the Yubico OTP protocol.
    ///
    /// Deliberately not a protocol requirement: unlike ``FIDOConnection/mtu`` this does not vary by
    /// device, and the framing layer relies on it being 8, so a conformance must not be able to
    /// claim otherwise.
    public var reportSize: Int { otpFeatureReportSize }
}
