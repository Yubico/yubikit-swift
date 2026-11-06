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

/// ML-KEM keys and parameter sets.
public enum MLKEM: Sendable {
    /// Algorithm parameter set.
    public enum ParameterSet: Sendable, CaseIterable {
        case mlKEM512
        case mlKEM768
        case mlKEM1024

        /// Encoded public-key size in bytes.
        public var publicKeyByteCount: Int {
            switch self {
            case .mlKEM512: 800
            case .mlKEM768: 1184
            case .mlKEM1024: 1568
            }
        }

        /// Encapsulated ciphertext size in bytes.
        public var ciphertextByteCount: Int {
            switch self {
            case .mlKEM512: 768
            case .mlKEM768: 1088
            case .mlKEM1024: 1568
            }
        }

        var oid: Data {
            let suffix: UInt8 =
                switch self {
                case .mlKEM512: 1
                case .mlKEM768: 2
                case .mlKEM1024: 3
                }
            return Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, suffix])
        }
    }

    /// Raw public key and its parameter set.
    public struct PublicKey: Sendable, Equatable {
        public let parameterSet: ParameterSet
        public let keyData: Data

        /// Creates a public key after checking its encoded length.
        public init?(keyData: Data, parameterSet: ParameterSet) {
            guard keyData.count == parameterSet.publicKeyByteCount else { return nil }
            self.keyData = keyData
            self.parameterSet = parameterSet
        }
    }

    /// Private-key seed for importing into a PIV slot.
    public struct PrivateKey: Sendable, Equatable {
        public let parameterSet: ParameterSet
        /// The 64-byte private-key seed.
        public let seed: Data

        /// Creates an importable private key from its seed.
        public init?(seed: Data, parameterSet: ParameterSet) {
            guard seed.count == 64 else { return nil }
            self.seed = seed
            self.parameterSet = parameterSet
        }
    }
}
