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

import ArgumentParser
import Foundation
import Shield
import YubiKit

// MARK: - Shared Helper Functions

extension PublicKey {
    // Convert YubiKit PublicKey to SecKey for certificate/CSR operations
    func toSecKey(slot: PIV.Slot, operation: String) throws -> SecKey {
        let secKey: SecKey?
        switch self {
        case .ed25519:
            throw PIVToolError.unsupportedOperation(
                operation: operation,
                reason: "Ed25519 keys are not currently supported for \(operation)"
            )
        case .x25519:
            throw PIVToolError.unsupportedOperation(
                operation: operation,
                reason: "X25519 keys cannot be used for \(operation) (key agreement only)"
            )
        case let .rsa(rsaKey):
            secKey = rsaKey.makeSecKey()
        case let .ec(ecKey):
            secKey = ecKey.makeSecKey()
        }

        guard let key = secKey else {
            throw PIVToolError.generic("Failed to create SecKey from public key in slot \(slot)")
        }

        return key
    }
}

extension GenerateCertificate {
    func createSelfSignedCertificate(
        publicKey: PublicKey,
        keyType: PIV.KeyType,
        slot: PIV.Slot,
        validDays: Int,
        hashAlgorithm: PIV.HashAlgorithm,
        session: PIVSession
    ) async throws -> X509Cert {
        // Convert YubiKit public key to macOS SecKey for certificate operations
        let secKey = try publicKey.toSecKey(slot: slot, operation: "certificate operations")

        // Hardcoded
        let subjectName = try Name("Yubikit")

        // Create certificate using Shield's Certificate.Builder
        let shieldCert = try? await ShieldX509.Certificate.Builder()
            .subject(name: subjectName)
            .issuer(name: subjectName)  // Self-signed: issuer = subject
            .publicKey(publicKey: secKey)
            .valid(for: TimeInterval(validDays * 24 * 60 * 60))  // Convert days to seconds
            .buildWithPIV(
                slot: slot,
                session: session,
                keyType: keyType,
                algorithm: hashAlgorithm
            )

        guard let cert = shieldCert else {
            throw PIVToolError.generic("Certificate generation failed: buildWithPIV returned nil")
        }

        // Convert Shield Certificate to YubiKit X509Cert
        let derData = try Data(cert.encoded())
        return X509Cert(der: derData)
    }
}

extension RequestCertificate {
    func createCertificateSigningRequest(
        publicKey: PublicKey,
        keyType: PIV.KeyType,
        slot: PIV.Slot,
        hashAlgorithm: PIV.HashAlgorithm,
        session: PIVSession
    ) async throws -> Data {
        // Convert YubiKit public key to macOS SecKey for CSR operations
        let secKey = try publicKey.toSecKey(slot: slot, operation: "CSR generation")

        // Hardcoded
        let subjectName = try Name("Yubikit")

        // Create CSR using Shield's CertificationRequest.Builder
        let csr = try await ShieldX509.CertificationRequest.Builder()
            .subject(name: subjectName)
            .publicKey(publicKey: secKey)
            .buildWithPIV(
                slot: slot,
                session: session,
                keyType: keyType,
                algorithm: hashAlgorithm
            )

        guard let csr = csr else {
            throw PIVToolError.exportFailed(reason: "Failed to build CSR")
        }

        // Return the DER-encoded CSR data
        return try Data(csr.encoded())
    }
}

extension Name {
    init(_ subject: String) throws {
        self = try NameBuilder()
            .add(subject, forTypeName: "CN")
            .name
    }
}
