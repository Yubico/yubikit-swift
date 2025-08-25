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

import CryptoTokenKit
import SwiftASN1
import YubiKit

extension PublicKey: DerRepresentable {
    var der: Data {
        switch self {
        case let .rsa(key): key.der
        case let .ec(key): key.der
        case let .ed25519(key): key.der
        case let .x25519(key): key.der
        }
    }

    // Get PEM representation of the public key
    var pemRepresentation: String {
        let pemDoc = PEMDocument(type: "PUBLIC KEY", derBytes: [UInt8](der))
        return pemDoc.pemString
    }
}
