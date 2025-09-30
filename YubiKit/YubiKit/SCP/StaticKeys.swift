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

import CryptoKit
import Foundation

/// Static keys for Secure Channel Protocol (SCP) operations.
/// Contains encryption, MAC, and optionally data encryption keys used in SCP03/SCP11 sessions.
public struct StaticKeys: Sendable {

    private static let defaultKey: Data = Data([
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ])

    /// The static encryption key.
    let enc: Data

    /// The static MAC key.
    let mac: Data

    /// The optional data encryption key.
    let dek: Data?

    /// Creates static keys for SCP operations.
    /// - Parameters:
    ///   - enc: The encryption key.
    ///   - mac: The MAC key.
    ///   - dek: The optional data encryption key.
    public init(enc: Data, mac: Data, dek: Data?) {
        self.enc = enc
        self.mac = mac
        self.dek = dek
    }

    /// Returns the default static keys used for SCP operations.
    /// - Returns: A `StaticKeys` instance with default key values.
    public static func defaultKeys() -> StaticKeys {
        StaticKeys(enc: defaultKey, mac: defaultKey, dek: defaultKey)
    }

    func derive(context: Data) -> SCPSessionKeys {
        SCPSessionKeys(
            senc: try! Self.deriveKey(key: enc, t: 0x4, context: context, l: 0x80),
            smac: try! Self.deriveKey(key: mac, t: 0x6, context: context, l: 0x80),
            srmac: try! Self.deriveKey(key: mac, t: 0x7, context: context, l: 0x80),
            dek: dek
        )
    }

    static func deriveKey(key: Data, t: Int8, context: Data, l: Int16) throws(EncryptionError) -> Data {
        var i = Data(count: 11)
        i.append(t.data)
        i.append(UInt8(0).data)
        i.append(l.bigEndian.data)
        i.append(UInt8(1).data)
        i.append(context)

        let digest = try i.aescmac(key: key)
        return digest.prefix(Int(l / 8))
    }
}
