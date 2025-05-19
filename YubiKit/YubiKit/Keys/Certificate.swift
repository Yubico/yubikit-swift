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

// X.509
public struct Certificate: Sendable {
    // X.509 DER representation
    public let der: Data

    public init(der: Data) {
        self.der = der
    }

    public func asSecCertificate() -> SecCertificate? {
        SecCertificateCreateWithData(nil, der as CFData)
    }
}

public extension Certificate {
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
            guard let keySize = RSA.KeySize(rawValue: attributes[kSecAttrKeySizeInBits] as! Int) else {
                return nil // unsupported RSA keySize
            }

            let key = RSA.PublicKey(size: keySize, pkcs1: blob)
            return key.map { .rsa($0) }

        case kSecAttrKeyTypeECSECPrimeRandom:
            let key = EC.PublicKey(uncompressedRepresentation: blob)
            return key.map { .ec($0) }
        default:
            return nil // unsupported
        }
    }
}
