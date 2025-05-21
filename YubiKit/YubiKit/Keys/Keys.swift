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

/// # Keys
/// Protocols and enums for generic cryptographic key handling (RSA and EC).

public enum CryptoKeyKind: Equatable {
    /// Kind of cryptographic key (RSA or EC), with associated parameters.
    case rsa(RSA.KeySize)
    case ec(EC.Curve)
}

/// Protocol for any supported cryptographic key.
public protocol CryptoKey: Sendable, Equatable {
    /// The kind (RSA or EC) and parameters of this key.
    var kind: CryptoKeyKind { get }
}

/// Generic public key (RSA or EC).
public enum PublicKey: CryptoKey {
    case ec(EC.PublicKey)
    case rsa(RSA.PublicKey)

    /// The kind (RSA or EC) and parameters of this key.
    public var kind: CryptoKeyKind {
        switch self {
        case let .ec(key):
            return .ec(key.curve)
        case let .rsa(key):
            return .rsa(key.size)
        }
    }
}

/// Generic private key (RSA or EC).
public enum PrivateKey: CryptoKey {
    case ec(EC.PrivateKey)
    case rsa(RSA.PrivateKey)

    /// The kind (RSA or EC) and parameters of this key.
    public var kind: CryptoKeyKind {
        switch self {
        case let .ec(key):
            return .ec(key.curve)
        case let .rsa(key):
            return .rsa(key.size)
        }
    }
}

// MARK: - Downcast helpers
public extension PublicKey {
    /// Returns the EC public key if this key is EC, otherwise nil.
    func asEC() -> EC.PublicKey? {
        switch self {
        case let .ec(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the RSA public key if this key is RSA, otherwise nil.
    func asRSA() -> RSA.PublicKey? {
        switch self {
        case let .rsa(key):
            return key
        default:
            return nil
        }
    }
}

public extension PrivateKey {
    /// Returns the EC private key if this key is EC, otherwise nil.
    func asEC() -> EC.PrivateKey? {
        switch self {
        case let .ec(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the RSA private key if this key is RSA, otherwise nil.
    func asRSA() -> RSA.PrivateKey? {
        switch self {
        case let .rsa(key):
            return key
        default:
            return nil
        }
    }
}
