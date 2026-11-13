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

public enum WiredSmartCardConnection: Sendable {
    /// Establishes a Lightning or SmartCard connection to a YubiKey.
    ///
    /// Call this method to connect to a YubiKey using a wired interface such as Lightning or SmartCard.
    /// The method will suspend until a compatible YubiKey is detected and a connection is established.
    ///
    /// - Returns: A ``SmartCardConnection`` instance representing the established wired connection.
    /// - Throws: An error if a connection could not be established.
    ///
    /// ```swift
    /// let wiredConnection = try await WiredSmartCardConnection.makeConnection()
    /// ```
    public static func makeConnection() async throws(SmartCardConnectionError) -> SmartCardConnection {
        #if os(iOS)
        if TargetDevice.hasLightningPort {
            return try await LightningSmartCardConnection()
        }
        #endif
        return try await USBSmartCardConnection()
    }
}
