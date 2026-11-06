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
import Foundation

extension PIVSession {
    /// Signs a message with ML-DSA. The device hashes the message internally.
    /// - Parameter context: An optional context string, at most 255 bytes.
    public func sign(
        _ message: Data,
        in slot: PIV.Slot,
        keyType: PIV.MLDSAKey,
        context: Data = Data()
    ) async throws(PIVSessionError) -> Data {
        guard context.count <= 255 else {
            throw .illegalArgument("ML-DSA context exceeds 255 bytes", source: .here())
        }
        var operands: [TKBERTLVRecord] = []
        if !context.isEmpty { operands.append(TKBERTLVRecord(tag: 0x87, value: context)) }
        operands.append(TKBERTLVRecord(tag: 0x81, value: message))
        return try await usePrivateKeyInSlot(slot: slot, keyType: .mlDSA(keyType.parameterSet), operands: operands)
    }

    /// Signs an externally computed ML-DSA message representative μ (FIPS 204), exactly 64 bytes.
    public func sign(
        externalMu: Data,
        in slot: PIV.Slot,
        keyType: PIV.MLDSAKey
    ) async throws(PIVSessionError) -> Data {
        guard externalMu.count == 64 else {
            throw .illegalArgument("ML-DSA external mu must be 64 bytes", source: .here())
        }
        return try await usePrivateKeyInSlot(
            slot: slot,
            keyType: .mlDSA(keyType.parameterSet),
            operands: [TKBERTLVRecord(tag: 0x88, value: externalMu)]
        )
    }

    /// Recovers the shared secret from an ML-KEM ciphertext using the private key in a slot.
    public func decapsulate(
        _ ciphertext: Data,
        in slot: PIV.Slot,
        keyType: PIV.MLKEMKey
    ) async throws(PIVSessionError) -> Data {
        guard ciphertext.count == keyType.parameterSet.ciphertextByteCount else {
            throw .illegalArgument("Invalid ML-KEM ciphertext length", source: .here())
        }
        return try await usePrivateKeyInSlot(
            slot: slot,
            keyType: .mlKEM(keyType.parameterSet),
            operands: [TKBERTLVRecord(tag: 0x86, value: ciphertext)]
        )
    }

    /// Imports an ML-DSA private-key seed. Requires ML-DSA support and management-key authentication.
    @discardableResult
    public func putPrivateKey(
        _ key: MLDSA.PrivateKey,
        in slot: PIV.Slot,
        pinPolicy: PIV.PinPolicy,
        touchPolicy: PIV.TouchPolicy
    ) async throws(PIVSessionError) -> PIV.MLDSAKey {
        try await importKey(
            keyType: .mlDSA(key.parameterSet),
            keyData: TKBERTLVRecord(tag: 0x09, value: key.seed).data,
            slot: slot,
            pinPolicy: pinPolicy,
            touchPolicy: touchPolicy
        )
        return .mlDSA(key.parameterSet)
    }

    /// Imports an ML-KEM private-key seed. Requires ML-KEM support and management-key authentication.
    @discardableResult
    public func putPrivateKey(
        _ key: MLKEM.PrivateKey,
        in slot: PIV.Slot,
        pinPolicy: PIV.PinPolicy,
        touchPolicy: PIV.TouchPolicy
    ) async throws(PIVSessionError) -> PIV.MLKEMKey {
        try await importKey(
            keyType: .mlKEM(key.parameterSet),
            keyData: TKBERTLVRecord(tag: 0x0a, value: key.seed).data,
            slot: slot,
            pinPolicy: pinPolicy,
            touchPolicy: touchPolicy
        )
        return .mlKEM(key.parameterSet)
    }
}
