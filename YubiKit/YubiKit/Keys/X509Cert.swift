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

/// X.509 certificate representation with DER encoding support.
/// Provides methods for working with SecCertificate and extracting cryptographic keys.
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

extension X509Cert {
    /// Extracts the public key from this certificate and returns it as a PublicKey.
    /// Returns nil if unsupported or extraction fails.
    public var publicKey: PublicKey? {
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
extension SecKey {
    fileprivate func asPublicKey() -> PublicKey? {
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
            return nil  // some error we can read and throw here
        }

        switch keyType {
        case kSecAttrKeyTypeRSA:
            let key = RSA.PublicKey(pkcs1: blob)

            guard let keySize = RSA.KeySize(rawValue: attributes[kSecAttrKeySizeInBits] as! Int),
                keySize == key?.size
            else {
                return nil  // unsupported RSA keySize
            }

            return key.map { .rsa($0) }

        case kSecAttrKeyTypeECSECPrimeRandom:

            return [EC.Curve.secp256r1, EC.Curve.secp384r1]
                .compactMap { EC.PublicKey(uncompressedPoint: blob, curve: $0) }
                .map { PublicKey.ec($0) }
                .first

        default:

            // other keyTypes not supported by the Security framework
            if let key = Ed25519.PublicKey(keyData: blob) {
                return .ed25519(key)
            } else if let key = X25519.PublicKey(keyData: blob) {
                return .x25519(key)
            }

            return nil  // unsupported
        }
    }
}
