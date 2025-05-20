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

/// # Certificate
/// X.509 Certificate wrapper for DER encoding and public key extraction.
/// Provides methods for working with SecCertificate and extracting cryptographic keys.
///
import Foundation

public struct X509Cert: Sendable {
    /// X.509 DER-encoded certificate data.
    public let der: Data

    /// Initialize a certificate from DER data.
    /// - Parameter der: The DER-encoded certificate data.
    public init(der: Data) {
        self.der = der
    }

    /// Returns this certificate as a SecCertificate.
    /// - Returns: The native SecCertificate, or nil if DER is invalid.
    public func asSecCertificate() -> SecCertificate? {
        SecCertificateCreateWithData(nil, der as CFData)
    }
}

public extension X509Cert {
    /// Converts a SecKey to a PublicKey (.rsa or .ec).
    /// Returns nil if unsupported or extraction fails.
    var publicKey: PublicKey? {
        guard let cert = asSecCertificate() else {
            // invalid der
            return nil
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates(cert, policy, &trust)
        guard status == errSecSuccess, let trust = trust else {
            // trust creation failed
            return nil
        }
        guard let key = SecTrustCopyKey(trust) else {
            // key extraction failed
            return nil
        }
        return key.asPublicKey()
    }
}


// MARK: - Private helper
private extension SecKey {
    func asPublicKey() -> PublicKey? {
        let attributes = SecKeyCopyAttributes(self) as! [CFString: Any]

        let keyClass = attributes[kSecAttrKeyClass] as! CFString
        let keyType = attributes[kSecAttrKeyType] as! CFString

        // must be public
        guard keyClass == kSecAttrKeyClassPublic else {
            return nil
        }

        // This returns a blob in the PKCS #1 format for an RSA key
        // and ANSI X9.63 - 0x04 || X || Y for EC key
        var error: Unmanaged<CFError>?
        guard let blob = SecKeyCopyExternalRepresentation(self, &error) as Data? else {
            return nil // some error we can read and throw here
        }

        switch keyType {
        case kSecAttrKeyTypeRSA:
            let key = RSA.PublicKey(pkcs1: blob)

            guard let keySize = RSA.KeySize(rawValue: attributes[kSecAttrKeySizeInBits] as! Int),
                  keySize == key?.size else {
                return nil // unsupported RSA keySize
            }

            return key.map { .rsa($0) }

        case kSecAttrKeyTypeECSECPrimeRandom:
            let key = EC.PublicKey(uncompressedPoint: blob)
            return key.map { .ec($0) }
        default:
            return nil // unsupported
        }
    }
}
