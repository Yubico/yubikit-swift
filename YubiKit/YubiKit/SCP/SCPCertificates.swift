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


/*
import Foundation
import Security

/// Represents a chain of SCP certificates, including optional root CA and leaf certificates.
public struct SCPCertificates {
    /// Root CA certificate if present
    public let ca: SecCertificate?
    /// Intermediate certificate bundle (excluding root CA and leaf)
    public let bundle: [SecCertificate]
    /// Leaf certificate (end-entity), if its keyUsage indicates digitalSignature
    public let leaf: SecCertificate?

    public init(ca: SecCertificate?, bundle: [SecCertificate], leaf: SecCertificate?) {
        self.ca = ca
        self.bundle = bundle
        self.leaf = leaf
    }

    /// Build SCPCertificates from an optional list of certificates
    /// - Parameter certificates: Array of SecCertificate or nil
    /// - Returns: Ordered chain: root CA at front (if any), intermediates, and optional leaf removed
    public static func from(_ certificates: [SecCertificate]?) -> SCPCertificates? {
        // If no certificates provided, return empty structure
        guard var certs = certificates, !certs.isEmpty else {
            return SCPCertificates(ca: nil, bundle: [], leaf: nil)
        }

        var ca: SecCertificate?
        var seenSerial: Data?

        // Start ordering: take first as presumed root
        var ordered: [SecCertificate] = [certs.removeFirst()]

        // Continue until all certs are placed
        while !certs.isEmpty {
            let head = ordered.first!
            let tail = ordered.last!
            let cert = certs.removeFirst()

            // If cert is self-signed, treat as root CA
            if isIssued(by: cert, issuer: cert) {
                ordered.insert(cert, at: 0)
                ca = ordered.first
                continue
            }

            // If cert issued by current tail, append as next intermediate
            if isIssued(by: cert, issuer: tail) {
                ordered.append(cert)
                continue
            }

            // If current head issued by cert, prepend above root
            if isIssued(by: head, issuer: cert) {
                ordered.insert(cert, at: 0)
                continue
            }

            // Detect loops: same serial seen twice without placement
            if let seen = seenSerial, serialNumber(of: cert) == seen {
                // trace(message: "cannot decide the order of \(cert) in \(ordered)")
                return nil
            }

            // Retry later; mark this serial
            certs.append(cert)
            seenSerial = serialNumber(of: cert)
        }

        // Remove root CA from intermediates
        if ca != nil { ordered.removeFirst() }

        var leaf: SecCertificate?
        // Check last cert for digitalSignature usage (keyUsage index 4)
        if let last = ordered.last,
           let values = SecCertificateCopyValues(last, [kSecOIDKeyUsage] as CFArray, nil) as? [CFString: Any],
           let usageDict = values[kSecOIDKeyUsage] as? [CFString: Any],
           let usageArray = usageDict[kSecPropertyKeyValue] as? [Bool],
           usageArray.count > 4, usageArray[4] {
            leaf = last
            ordered.removeLast()
        }

        return SCPCertificates(ca: ca, bundle: ordered, leaf: leaf)
    }

    /// Check if `subject` certificate is issued by `issuer` certificate
    /// - Parameters:
    ///   - subject: certificate whose issuer is tested
    ///   - issuer: certificate to compare as issuer
    /// - Returns: true if subject's issuer matches issuer's subject
    private static func isIssued(by subject: SecCertificate, issuer: SecCertificate) -> Bool {
        guard let issuerSeq = SecCertificateCopyNormalizedIssuerSequence(subject) as Data?,
              let subjectSeq = SecCertificateCopyNormalizedSubjectSequence(issuer) as Data? else {
            return false
        }
        return issuerSeq == subjectSeq
    }

    /// Extract serial number data from a certificate
    /// - Parameter cert: certificate to extract serial number
    /// - Returns: raw serial number bytes
    private static func serialNumber(of cert: SecCertificate) -> Data {
        guard let vals = SecCertificateCopyValues(cert, [kSecOIDX509V1SerialNumber] as CFArray, nil) as? [CFString: Any],
              let serialDict = vals[kSecOIDX509V1SerialNumber] as? [CFString: Any],
              let value = serialDict[kSecPropertyKeyValue] as? Data else {
            return Data()
        }
        return value
    }
}
*/
