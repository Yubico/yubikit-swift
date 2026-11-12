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

/// ML-DSA keys and parameter sets.
public enum MLDSA: Sendable {
    /// Algorithm parameter set.
    public enum ParameterSet: Sendable, CaseIterable {
        case mlDSA44
        case mlDSA65
        case mlDSA87

        /// Encoded public-key size in bytes.
        public var publicKeyByteCount: Int {
            switch self {
            case .mlDSA44: 1312
            case .mlDSA65: 1952
            case .mlDSA87: 2592
            }
        }

        var oid: Data {
            let suffix: UInt8 =
                switch self {
                case .mlDSA44: 17
                case .mlDSA65: 18
                case .mlDSA87: 19
                }
            return Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, suffix])
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

        #if compiler(>=6.2)
        /// Verifies a signature locally using CryptoKit.
        /// ML-DSA-44 is not supported by CryptoKit.
        @available(iOS 26, macOS 26, *)
        public func isValidSignature(_ signature: Data, for message: Data, context: Data = Data()) throws -> Bool {
            try Crypto.MLDSA.isValidSignature(signature, for: message, context: context, key: self)
        }
        #endif
    }

    /// Private-key seed for importing into a PIV slot.
    public struct PrivateKey: Sendable, Equatable {
        public let parameterSet: ParameterSet
        /// The 32-byte private-key seed.
        public let seed: Data

        /// Creates an importable private key from its seed.
        public init?(seed: Data, parameterSet: ParameterSet) {
            guard seed.count == 32 else { return nil }
            self.seed = seed
            self.parameterSet = parameterSet
        }
    }
}
