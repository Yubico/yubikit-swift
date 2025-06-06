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

/// The touch policy of a private key defines whether or not a user presence check (physical touch) is required to use the key.
public enum PIVTouchPolicy: UInt8 {
    /// The default behavior for the particular key slot is used, which is always `.never`.
    case defaultPolicy = 0x0
    /// Touch is never required for using the key.
    case never = 0x1
    /// Touch is always required for using the key.
    case always = 0x2
    /// Touch is required, but cached for 15s after use, allowing multiple uses.
    case cached = 0x3
}

/// The PIN policy of a private key defines whether or not a PIN is required to use the key.
public enum PIVPinPolicy: UInt8 {
    /// The default behavior for the particular key slot is used.
    case defaultPolicy = 0x0
    /// The PIN is never required for using the key.
    case never = 0x1
    /// The PIN must be verified for the session, prior to using the key.
    case once = 0x2
    /// The PIN must be verified each time the key is to be used, just prior to using it.
    case always = 0x3
    /// PIN or biometrics must be verified for the session, prior to using the key.
    case matchOnce = 0x4
    /// PIN or biometrics must be verified each time the key is to be used, just prior to using it.
    case matchAlways = 0x5
}

/// The slot to use in the PIV application.
public enum PIVSlot: UInt8 {
    case authentication = 0x9a
    case signature = 0x9c
    case keyManagement = 0x9d
    case cardAuth = 0x9e
    case attestation = 0xf9

    var objectId: Data {
        switch self {
        case .authentication:
            return Data([0x5f, 0xc1, 0x05])
        case .signature:
            return Data([0x5f, 0xc1, 0x0a])
        case .keyManagement:
            return Data([0x5f, 0xc1, 0x0b])
        case .cardAuth:
            return Data([0x5f, 0xc1, 0x01])
        case .attestation:
            return Data([0x5f, 0xff, 0x01])
        }
    }
}

// PIV key type.
public enum PIVKeyType: RawRepresentable, Equatable {

    case rsa(RSA.KeySize)
    case ecc(EC.Curve)

    // TODO:
    // 0xE0: Edwards Digital Signature Algorithm (EdDSA) key, using Curve25519
    // 0xE1: Elliptic-Curve Diffie-Hellman (ECDH) protocol key, using Curve25519
    //
    // Ed25519: ONLY be used for signing & X25519 ONLY be used for keyAgreement

    public var rawValue: UInt8 {
        switch self {
        case .rsa(let size):
            return switch size {
            case .bits1024: 0x06
            case .bits2048: 0x07
            case .bits3072: 0x05
            case .bits4096: 0x16
            }
        case .ecc(let curve):
            return switch curve {
            case .p256: 0x11
            case .p384: 0x14
            }
        }
    }

    public init?(rawValue: UInt8) {
        switch rawValue {
        case 0x06: self = .rsa(.bits1024)
        case 0x07: self = .rsa(.bits2048)
        case 0x05: self = .rsa(.bits3072)
        case 0x16: self = .rsa(.bits4096)

        case 0x11: self = .ecc(.p256)
        case 0x14: self = .ecc(.p384)

        default: return nil
        }
    }

    public init?(kind: CryptoKeyKind) {
        switch kind {
        case .rsa(let size):
            self = .rsa(size)
        case .ec(let curve):
            self = .ecc(curve)
        }
    }

    public var sizeInBits: Int {
        switch self {
        case .rsa(let keySize): keySize.rawValue
        case .ecc(let curve): curve.keySizeInBits
        }
    }

    public var sizeInBytes: Int {
        sizeInBits / 8
    }
}

/// Result of a pin verification.
public enum PIVVerifyPinResult: Equatable {
    /// Verification was successful. The associated value holds the number of pin retries left.
    case success(Int)
    /// Verification failed. The associated value holds the number of pin retries left.
    case fail(Int)
    /// PIN has been locked.
    case pinLocked
}

/// PIV session specific errors.
public enum PIVSessionError: Error {
    case invalidCipherTextLength
    case unsupportedOperation
    case dataParseError
    case unknownKeyType
    case invalidPin
    case pinLocked
    case invalidResponse
    case authenticationFailed
    case responseDataNotTLVFormatted
    case failedCreatingCertificate
    case badKeyLength
    case invalidInput
}

/// Metadata about the card management key.
public struct PIVManagementKeyMetadata {
    /// Whether or not the default card management key is set.
    public let isDefault: Bool
    /// The algorithm of key used for the Management Key.
    public let keyType: PIVManagementKeyType
    /// Whether or not the YubiKey sensor needs to be touched when performing authentication.
    public let touchPolicy: PIVTouchPolicy
}

/// Metadata about a key in a slot.
public struct PIVSlotMetadata {
    /// The algorithm and size of the key.
    public let keyType: PIVKeyType
    /// The PIN policy of a private key defines whether or not a PIN is required to use the key.
    public let pinPolicy: PIVPinPolicy
    /// The touch policy of a private key defines whether or not a user presence check (physical touch) is required to use the key.
    public let touchPolicy: PIVTouchPolicy
    /// Whether the key was generated on the YubiKey or imported.
    public let generated: Bool
    /// Returns the public key corresponding to the key in the slot.
    public let publicKey: PublicKey
}

/// Metadata about the PIN or PUK.
public struct PIVPinPukMetadata {
    /// Whether or not the default PIN/PUK is set.
    public let isDefault: Bool
    /// The number of PIN/PUK attempts available after successful verification.
    public let retriesTotal: Int
    /// The number of PIN/PUK attempts currently remaining.
    public let retriesRemaining: Int
}

/// PIV management key type.
public enum PIVManagementKeyType: UInt8 {
    /// 3-des (default)
    case tripleDES = 0x03
    /// AES-128
    case AES128 = 0x08
    /// AES-192
    case AES192 = 0x0a
    /// AES-256
    case AES256 = 0x0c

    /// The length of the key.
    var keyLength: Int {
        switch self {
        case .tripleDES, .AES192:
            return 24
        case .AES128:
            return 16
        case .AES256:
            return 32
        }
    }

    /// The length of the challenge.
    var challengeLength: Int {
        switch self {
        case .tripleDES:
            return 8
        case .AES128, .AES192, .AES256:
            return 16
        }
    }
}

/// Metadata about a Bio multi-protocol YubiKey.
public struct PIVBioMetadata {
    /// Indicates whether biometrics are configured or not (fingerprints enrolled or not).
    ///
    /// A false return value indicates a YubiKey Bio without biometrics configured and hence the
    /// client should fallback to a PIN based authentication.
    public let isConfigured: Bool

    /// Value of biometric match retry counter which states how many biometric match retries
    /// are left until a YubiKey Bio is blocked.
    ///
    /// If this method returns 0 and ``isConfigured`` returns true, the device is blocked for
    /// biometric match and the client should invoke PIN based authentication to reset the biometric
    /// match retry counter.
    public let attemptsRemaining: UInt

    /// Indicates whether a temporary PIN has been generated in the YubiKey in relation to a
    /// successful biometric match. Is true if a temporary PIN has been generated.
    public let temporaryPin: Bool

    internal init(isConfigured: Bool, attemptsRemaining: UInt, temporaryPin: Bool) {
        self.isConfigured = isConfigured
        self.attemptsRemaining = attemptsRemaining
        self.temporaryPin = temporaryPin
    }
}
