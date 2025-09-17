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

/// Key parameters for Secure Channel Protocol 03 (SCP03).
/// Contains the key reference and static keys needed for establishing an SCP03 secure channel.
public struct SCP03KeyParams: SCPKeyParams, Sendable {

    /// The key reference containing key ID and version.
    public let keyRef: SCPKeyRef

    /// The static keys for SCP03 operations.
    public let staticKeys: StaticKeys

    /// Creates SCP03 key parameters.
    /// - Parameters:
    ///   - keyRef: The key reference with KID and KVN
    ///   - staticKeys: The static keys for encryption and MAC operations.
    /// - Throws: `SCPError.illegalArgument` if the KID is invalid for SCP03.
    public init(keyRef: SCPKeyRef, staticKeys: StaticKeys) throws(SCPError) {
        if 0xFF & keyRef.kid > 3 {
            throw .illegalArgument("Invalid KID for SCP03")
        }
        self.keyRef = keyRef
        self.staticKeys = staticKeys
    }
}
