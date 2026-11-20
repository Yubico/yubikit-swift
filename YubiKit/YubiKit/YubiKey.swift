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

/// A snapshot of a YubiKey's metadata and product name.
///
/// Initialize before creating application sessions: discovery can select applications
/// on the connection. The caller retains ownership of the connection.
/// Create a new snapshot to reflect subsequent configuration changes.
public struct YubiKey: Sendable {
    /// The discovered metadata. Older keys may provide incomplete or inferred information,
    /// including unknown enabled capabilities.
    public let deviceInfo: DeviceInfo

    /// The reported product name, or a name inferred from the discovered metadata.
    public let deviceName: String

    /// Reads a snapshot over a smart-card connection.
    public init(connection: SmartCardConnection) async throws {
        deviceInfo = try await DeviceInfo.read(connection: connection)
        deviceName = deviceInfo.deviceName
    }

    /// Reads a snapshot over a FIDO connection.
    public init(connection: FIDOConnection) async throws {
        deviceInfo = try await DeviceInfo.read(connection: connection)
        deviceName = deviceInfo.deviceName
    }

    /// Reads a snapshot over an OTP connection.
    public init(connection: OTPConnection) async throws {
        deviceInfo = try await DeviceInfo.read(connection: connection)
        deviceName = deviceInfo.deviceName
    }
}
