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
import YubiKit

func signCertificateData(
    _ data: Data,
    in slot: PIV.Slot,
    keyType: PIV.KeyType,
    hash: PIV.HashAlgorithm,
    session: PIVSession
) async throws -> Data {
    do {
        switch keyType {
        case .rsa(let size): return try await session.sign(data, in: slot, keyType: .rsa(size), using: .pkcs1v15(hash))
        case .ec(let curve): return try await session.sign(data, in: slot, keyType: .ec(curve), using: .hash(hash))
        case .ed25519: return try await session.sign(data, in: slot, keyType: .ed25519)
        case .mlDSA(let parameters): return try await session.sign(data, in: slot, keyType: .mlDSA(parameters))
        case .x25519, .mlKEM: throw ToolError("Key agreement keys cannot sign certificates or CSRs.")
        }
    } catch { throw pivError(error) }
}
