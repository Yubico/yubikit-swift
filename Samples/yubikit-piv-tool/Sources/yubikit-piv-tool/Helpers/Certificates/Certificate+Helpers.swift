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
import PotentASN1
import Shield
import SwiftASN1
import YubiKit

// MARK: - Shared Helper Functions

extension PublicKey {
    // Convert YubiKit PublicKey to SecKey for certificate/CSR operations
    func toSecKey(slot: PIV.Slot, operation: String) throws -> SecKey {
        let secKey: SecKey?
        switch self {
        case .ed25519:
            throw ToolError(
                "Unsupported operation: \(operation).\n\tEd25519 keys are not currently supported for \(operation)"
            )
        case .x25519:
            throw ToolError(
                "Unsupported operation: \(operation).\n\tX25519 keys cannot be used for \(operation) (key agreement only)"
            )
        case .mlDSA, .mlKEM:
            throw ToolError("Unsupported key type for \(operation).")
        case let .rsa(rsaKey):
            secKey = rsaKey.makeSecKey()
        case let .ec(ecKey):
            secKey = ecKey.makeSecKey()
        }

        guard let key = secKey else {
            throw ToolError("Key conversion failed for slot \(slot).")
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
        switch keyType {
        case .mlDSA:
            return X509Cert(
                der: try await DirectCertificate.build(
                    publicKey: publicKey,
                    subject: subject,
                    days: validDays,
                    slot: slot,
                    type: keyType,
                    hash: hashAlgorithm,
                    session: session
                )
            )
        default: break
        }
        // Convert YubiKit public key to macOS SecKey for certificate operations
        let secKey = try publicKey.toSecKey(slot: slot, operation: "certificate operations")

        // Hardcoded
        let subjectName = try Name(subject)

        // Create certificate using Shield's Certificate.Builder
        let shieldCert = try await ShieldX509.Certificate.Builder()
            .subject(name: subjectName)
            .issuer(name: subjectName)  // Self-signed: issuer = subject
            .publicKey(publicKey: secKey)
            .valid(for: TimeInterval(validDays) * 24 * 60 * 60)  // Convert days to seconds
            .buildWithPIV(
                slot: slot,
                session: session,
                keyType: keyType,
                algorithm: hashAlgorithm
            )

        guard let cert = shieldCert else {
            throw ToolError("Certificate generation failed: buildWithPIV returned nil")
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
        switch keyType {
        case .mlDSA:
            return try await DirectCertificate.request(
                publicKey: publicKey,
                subject: subject,
                slot: slot,
                type: keyType,
                hash: hashAlgorithm,
                session: session
            )
        default: break
        }
        // Convert YubiKit public key to macOS SecKey for CSR operations
        let secKey = try publicKey.toSecKey(slot: slot, operation: "CSR generation")

        // Hardcoded
        let subjectName = try Name(subject)

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
            throw ToolError("Export failed: Failed to build CSR")
        }

        // Return the DER-encoded CSR data
        return try Data(csr.encoded())
    }
}

extension Name {
    fileprivate init(_ subject: String) throws {
        self = try NameBuilder()
            .add(subject, forTypeName: "CN")
            .name
    }
}

// Direct-signature keys cannot be represented by SecKey. Keep their existing SDK SPKI intact.
private enum DirectCertificate {
    static func build(
        publicKey: PublicKey,
        subject: String,
        days: Int,
        slot: PIV.Slot,
        type: PIV.KeyType,
        hash: PIV.HashAlgorithm,
        session: PIVSession
    ) async throws -> Data {
        let algorithm = try algorithmIdentifier(publicKey)
        let name = try ASN1Encoder(schema: ShieldX509.Schemas.Name).encode(Name(subject))
        let now = Date()
        let tbs = try sequence { coder in
            try coder.appendConstructedNode(identifier: ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) {
                try $0.serialize(2)
            }
            try coder.serialize(UInt64.random(in: 1...UInt64.max))
            coder.serializeRawBytes(algorithm)
            coder.serializeRawBytes(name)
            try coder.appendConstructedNode(identifier: .sequence) {
                try time(now, into: &$0)
                try time(now.addingTimeInterval(TimeInterval(days) * 86400), into: &$0)
            }
            coder.serializeRawBytes(name)
            coder.serializeRawBytes(publicKey.spki)
        }
        return try await signed(tbs, algorithm: algorithm, slot: slot, type: type, hash: hash, session: session)
    }

    static func request(
        publicKey: PublicKey,
        subject: String,
        slot: PIV.Slot,
        type: PIV.KeyType,
        hash: PIV.HashAlgorithm,
        session: PIVSession
    ) async throws -> Data {
        let name = try ASN1Encoder(schema: ShieldX509.Schemas.Name).encode(Name(subject))
        let info = try sequence {
            try $0.serialize(0)
            $0.serializeRawBytes(name)
            $0.serializeRawBytes(publicKey.spki)
            $0.appendConstructedNode(identifier: ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) { _ in }
        }
        return try await signed(
            info,
            algorithm: algorithmIdentifier(publicKey),
            slot: slot,
            type: type,
            hash: hash,
            session: session
        )
    }

    private static func algorithmIdentifier(_ publicKey: PublicKey) throws -> Data {
        let node = try DER.parse([UInt8](publicKey.spki))
        guard case .constructed(let children) = node.content else {
            throw ToolError("Invalid public-key encoding.")
        }
        var iterator = children.makeIterator()
        guard let algorithm = iterator.next() else { throw ToolError("Invalid public-key encoding.") }
        var coder = DER.Serializer()
        coder.serialize(algorithm)
        return Data(coder.serializedBytes)
    }

    private static func signed(
        _ info: Data,
        algorithm: Data,
        slot: PIV.Slot,
        type: PIV.KeyType,
        hash: PIV.HashAlgorithm,
        session: PIVSession
    ) async throws -> Data {
        let signature = try await signCertificateData(info, in: slot, keyType: type, hash: hash, session: session)
        return try sequence {
            $0.serializeRawBytes(info)
            $0.serializeRawBytes(algorithm)
            try $0.serialize(ASN1BitString(bytes: ArraySlice(signature)))
        }
    }

    private static func sequence(_ body: (inout DER.Serializer) throws -> Void) rethrows -> Data {
        var coder = DER.Serializer()
        try coder.appendConstructedNode(identifier: .sequence, body)
        return Data(coder.serializedBytes)
    }

    private static func time(_ date: Date, into coder: inout DER.Serializer) throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .gmt
        let fields = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        guard let year = fields.year, let month = fields.month, let day = fields.day,
            let hour = fields.hour, let minute = fields.minute, let second = fields.second
        else {
            throw ToolError("Invalid certificate date.")
        }
        if year < 2050 {
            try coder.serialize(
                UTCTime(year: year, month: month, day: day, hours: hour, minutes: minute, seconds: second)
            )
        } else {
            try coder.serialize(
                GeneralizedTime(
                    year: year,
                    month: month,
                    day: day,
                    hours: hour,
                    minutes: minute,
                    seconds: second,
                    fractionalSeconds: 0
                )
            )
        }
    }
}
