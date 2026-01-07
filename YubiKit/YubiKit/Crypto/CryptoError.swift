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

import CommonCrypto

/// Errors related to cryptographic operations.
public enum CryptoError: Error, Sendable {
    /// CommonCrypto cryptor operation failed.
    case cryptorError(CCCryptorStatus)

    /// Required data is missing for the cryptographic operation.
    case missingData

    /// The requested cryptographic algorithm is not supported.
    case unsupportedAlgorithm

    /// Secure random byte generation failed.
    case randomGenerationFailed

    /// The provided key is invalid or malformed.
    case invalidKey

    /// ECDH key agreement operation failed.
    case keyAgreementFailed

    /// Key derivation (PBKDF2) failed.
    case keyDerivationFailed(CCCryptorStatus)

    /// RSA or ECDSA signing operation failed.
    case signingFailed(Error?)

    /// RSA encryption operation failed.
    case encryptionFailed(Error?)

    /// RSA decryption operation failed.
    case decryptionFailed(Error?)

    /// Failed to create a cryptographic key.
    case keyCreationFailed(Error?)
}

/// Type alias for backward compatibility.
public typealias EncryptionError = CryptoError
