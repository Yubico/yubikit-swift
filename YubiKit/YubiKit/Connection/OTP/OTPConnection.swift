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

/// A low-level transport connection to the Yubico OTP application on a YubiKey.
///
/// Use an OTP connection to exchange 8-byte feature reports with the keyboard HID interface of the
/// YubiKey.
public protocol OTPConnection: Connection {

    /// Create a new OTPConnection to the YubiKey.
    ///
    /// The initializer attempts to open an OTP interface that is currently available.
    ///
    /// - Throws: ``OTPConnectionError/noDevicesFound`` if none is available, or
    ///   ``OTPConnectionError/busy`` if the selected device already has an open connection.
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
    /// The method attempts to open an OTP interface that is currently available.
    ///
    /// - Throws: ``OTPConnectionError/noDevicesFound`` if none is available, or
    ///   ``OTPConnectionError/busy`` if the selected device already has an open connection.
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
    public var reportSize: Int { otpFeatureReportSize }
}

let otpFeatureReportSize = 8
