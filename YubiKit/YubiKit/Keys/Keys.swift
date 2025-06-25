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
/// Protocols and enums for generic cryptographic key handling (RSA, EC, and Curve25519).

public enum CryptoKeyKind: Equatable {
    /// Kind of cryptographic key (RSA, EC, or Curve25519), with associated parameters.
    case rsa(RSA.KeySize)
    case ec(EC.Curve)
    case ed25519
    case x25519
}

/// Protocol for any supported cryptographic key.
public protocol CryptoKey: Sendable, Equatable {
    /// The kind (RSA, EC, or Curve25519) and parameters of this key.
    var kind: CryptoKeyKind { get }
}

/// Generic public key (RSA, EC, or Curve25519).
public enum PublicKey: CryptoKey {
    case ec(EC.PublicKey)
    case rsa(RSA.PublicKey)
    case ed25519(Curve25519.Ed25519.PublicKey)
    case x25519(Curve25519.X25519.PublicKey)

    /// The kind (RSA, EC, or Curve25519) and parameters of this key.
    public var kind: CryptoKeyKind {
        switch self {
        case let .ec(key):
            return .ec(key.curve)
        case let .rsa(key):
            return .rsa(key.size)
        case .ed25519:
            return .ed25519
        case .x25519:
            return .x25519
        }
    }
}

/// Generic private key (RSA, EC, or Curve25519).
public enum PrivateKey: CryptoKey {
    case ec(EC.PrivateKey)
    case rsa(RSA.PrivateKey)
    case ed25519(Curve25519.Ed25519.PrivateKey)
    case x25519(Curve25519.X25519.PrivateKey)

    /// The kind (RSA, EC, or Curve25519) and parameters of this key.
    public var kind: CryptoKeyKind {
        switch self {
        case let .ec(key):
            return .ec(key.curve)
        case let .rsa(key):
            return .rsa(key.size)
        case .ed25519:
            return .ed25519
        case .x25519:
            return .x25519
        }
    }
}

// MARK: - Downcast helpers
extension PublicKey {
    /// Returns the EC public key if this key is EC, otherwise nil.
    public func asEC() -> EC.PublicKey? {
        switch self {
        case let .ec(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the RSA public key if this key is RSA, otherwise nil.
    public func asRSA() -> RSA.PublicKey? {
        switch self {
        case let .rsa(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the Ed25519 public key if this key is Ed25519, otherwise nil.
    public func asEd25519() -> Curve25519.Ed25519.PublicKey? {
        switch self {
        case let .ed25519(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the X25519 public key if this key is X25519, otherwise nil.
    public func asX25519() -> Curve25519.X25519.PublicKey? {
        switch self {
        case let .x25519(key):
            return key
        default:
            return nil
        }
    }
}

extension PrivateKey {
    /// Returns the EC private key if this key is EC, otherwise nil.
    public func asEC() -> EC.PrivateKey? {
        switch self {
        case let .ec(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the RSA private key if this key is RSA, otherwise nil.
    public func asRSA() -> RSA.PrivateKey? {
        switch self {
        case let .rsa(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the Ed25519 private key if this key is Ed25519, otherwise nil.
    public func asEd25519() -> Curve25519.Ed25519.PrivateKey? {
        switch self {
        case let .ed25519(key):
            return key
        default:
            return nil
        }
    }

    /// Returns the X25519 private key if this key is X25519, otherwise nil.
    public func asX25519() -> Curve25519.X25519.PrivateKey? {
        switch self {
        case let .x25519(key):
            return key
        default:
            return nil
        }
    }
}
