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

extension SmartCardConnection {
    /// Reads the YubiKey's product name, including fallback identification for older keys.
    ///
    /// Selects applications on the connection. Read this before creating application sessions.
    /// Each access reads the device; the caller retains ownership of the connection.
    public var deviceName: String {
        get async throws {
            let info = try await DeviceInfo.read(connection: self)
            return info.deviceName
        }
    }
}

extension FIDOConnection {
    /// Reads the YubiKey's product name, including fallback identification for older keys.
    ///
    /// Each access reads the device. Read this before creating application sessions.
    /// The caller retains ownership of the connection.
    public var deviceName: String {
        get async throws {
            let info = try await DeviceInfo.read(connection: self)
            return info.deviceName
        }
    }
}

extension OTPConnection {
    /// Reads the YubiKey's product name, including fallback identification for older keys.
    ///
    /// Each access reads the device. Read this before creating application sessions.
    /// The caller retains ownership of the connection.
    public var deviceName: String {
        get async throws {
            let info = try await DeviceInfo.read(connection: self)
            return info.deviceName
        }
    }
}
