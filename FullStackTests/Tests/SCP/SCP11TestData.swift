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
import YubiKit
import CryptoKit

// Sourced from:
// https://github.com/Yubico/yubikey-manager/tree/main/tests/files/scp
//
enum Scp11TestData {

    // cert.ca-kloc.ecdsa.pem
    static let caCert = [SecCertificate](pem: caPem)![0]
    private static let caPem: String = """
-----BEGIN CERTIFICATE-----
MIIB2zCCAYGgAwIBAgIUSf59wIpCKOrNGNc5FMPTD9zDGVAwCgYIKoZIzj0EAwIw
KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y
NDA1MjgwOTIyMDlaFw0yNDA2MjcwOTIyMDlaMCoxKDAmBgNVBAMMH0V4YW1wbGUg
T0NFIFJvb3QgQ0EgQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASPrxfpSB/AvuvLKaCz1YTx68Xbtx8S9xAMfRGwzp5cXMdF8c7AWpUfeM3BQ26M
h0WPvyBJKhCdeK8iVCaHyr5Jo4GEMIGBMB0GA1UdDgQWBBQxqlVmn2Bn6B8z3P0E
/t5z5XGfPTASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjA8BgNV
HSABAf8EMjAwMA4GDCqGSIb8a2QACgIBFDAOBgwqhkiG/GtkAAoCASgwDgYMKoZI
hvxrZAAKAgEAMAoGCCqGSM49BAMCA0gAMEUCIHv8cgOzxq2n1uZktL9gCXSR85mk
TieYeSoKZn6MM4rOAiEA1S/+7ez/gxDl01ztKeoHiUiW4FbEG4JUCzIITaGxVvM=
-----END CERTIFICATE-----
"""

    // cert.ka-kloc.ecdsa.pem
    static let kaCert = [SecCertificate](pem: kaPem)![0]
    private static let kaPem: String = """
-----BEGIN CERTIFICATE-----
MIIB8DCCAZegAwIBAgIUf0lxsK1R+EydqZKLLV/vXhaykgowCgYIKoZIzj0EAwIw
KjEoMCYGA1UEAwwfRXhhbXBsZSBPQ0UgUm9vdCBDQSBDZXJ0aWZpY2F0ZTAeFw0y
NDA1MjgwOTIyMDlaFw0yNDA4MjYwOTIyMDlaMC8xLTArBgNVBAMMJEV4YW1wbGUg
T0NFIEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABMXbjb+Y33+GP8qUznrdZSJX9b2qC0VUS1WDhuTlQUfg/RBNFXb2/qWt
h/a+Ag406fV7wZW2e4PPH+Le7EwS1nyjgZUwgZIwHQYDVR0OBBYEFJzdQCINVBES
R4yZBN2l5CXyzlWsMB8GA1UdIwQYMBaAFDGqVWafYGfoHzPc/QT+3nPlcZ89MBIG
A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgIEMCwGA1UdIAEB/wQiMCAw
DgYMKoZIhvxrZAAKAgEoMA4GDCqGSIb8a2QACgIBADAKBggqhkjOPQQDAgNHADBE
AiBE5SpNEKDW3OehDhvTKT9g1cuuIyPdaXGLZ3iX0x0VcwIgdnIirhlKocOKGXf9
ijkE8e+9dTazSPLf24lSIf0IGC8=
-----END CERTIFICATE-----
"""

    // cert.oce.ecka.pem
    static let eckaCert = [SecCertificate](pem: eckaPem)![0]
    static let eckaPem: String = """
-----BEGIN CERTIFICATE-----
MIIBwjCCAWmgAwIBAgIUa5ACiACQn5/81kE0aTMkJ0j76a0wCgYIKoZIzj0EAwIw
LzEtMCsGA1UEAwwkRXhhbXBsZSBPQ0UgSW50ZXJtZWRpYXRlIENlcnRpZmljYXRl
MB4XDTI0MDUyODA5MjIwOVoXDTI0MDgyNjA5MjIwOVowIjEgMB4GA1UEAwwXRXhh
bXBsZSBPQ0UgQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASY
yRCUFDM7fb0iOwyaO4ayzp+vh7UhonFbCuzgYKMLHplN3r8cyQNuso0J5UqZUwVy
llE1EAF2Pu+RlJvtnYD2o3AwbjAdBgNVHQ4EFgQU6dH0CdJ18Nzbj3vamDW/rZl7
GvcwHwYDVR0jBBgwFoAUnN1AIg1UERJHjJkE3aXkJfLOVawwDgYDVR0PAQH/BAQD
AgMIMBwGA1UdIAEB/wQSMBAwDgYMKoZIhvxrZAAKAgEAMAoGCCqGSM49BAMCA0cA
MEQCIE2Fp0ybSmD5sZ6kvrpUJ14WAdHjUbUfFxXwLU4Dnn2tAiBmPMUa4DqpnnnN
Xfx/i/gUmwCTdA+dFrc1jWYZ8qVd6Q==
-----END CERTIFICATE-----
"""

    // sk.oce.ecka.pem
    static let secretKey = SecKey?(pem: secretKeyPem)!
    static let secretKeyPem = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTWGyQ5Nmm3WG0Hfc
NhjOla4n7fzKkiDN6t4Gjngfe6yhRANCAASYyRCUFDM7fb0iOwyaO4ayzp+vh7Uh
onFbCuzgYKMLHplN3r8cyQNuso0J5UqZUwVyllE1EAF2Pu+RlJvtnYD2
-----END PRIVATE KEY-----
"""
}

// MARK: - Private helpers to parse from PEM

private extension [SecCertificate] {
    init?(pem: String) {
        let regex = try! NSRegularExpression(pattern: "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", options: [.dotMatchesLineSeparators])
        let matches = regex.matches(in: pem, options: [], range: NSRange(location: 0, length: pem.utf16.count))

        var certs: [SecCertificate] = []

        for match in matches {
            if let range = Range(match.range(at: 1), in: pem) {
                let base64 = pem[range].replacingOccurrences(of: "\n", with: "")
                if let derData = Data(base64Encoded: base64),
                   let cert = SecCertificateCreateWithData(nil, derData as CFData) {
                    certs.append(cert)
                } else {
                    // Certificate parsing failed
                    return nil
                }
            }
        }

        self = certs
    }
}

private extension Optional where Wrapped == SecKey {
    init?(pem: String) {
        guard let pkcs8Key = try? P256.Signing.PrivateKey(pemRepresentation: pem) else {
            self = nil
            return
        }

        let rep = pkcs8Key.x963Representation as CFData

        var err: Unmanaged<CFError>?
        let attrs: NSDictionary = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 256
        ]

        guard let key = SecKeyCreateWithData(rep, attrs, &err) else {
            self = nil
            return
        }

        self = key
    }
}
