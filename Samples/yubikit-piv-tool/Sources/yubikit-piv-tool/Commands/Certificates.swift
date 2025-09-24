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
import CryptoKit
import Foundation
import ShieldX500
import ShieldX509
import SwiftASN1
import YubiKit

// MARK: - Certificate Management Commands

struct Certificates: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "PIV certificate operations (generate, import, export, delete, CSR)",
        subcommands: [
            GenerateCertificate.self,
            ExportCertificate.self,
            RequestCertificate.self,
            ImportCertificate.self,
            DeleteCertificate.self,
        ]
    )
}

struct GenerateCertificate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "generate",
        abstract: "Generate a self-signed certificate for an existing key"
    )

    // Requires an existing key in the slot (use `keys generate` first)
    @Argument(help: "PIV slot containing key for certificate generation")
    var slot: String

    // AUTHENTICATION: Management key required for certificate operations
    @Option(name: [.customShort("m"), .customLong("management-key")], help: "Management key")
    var managementKey: String?

    // PIN: Required for signing the certificate with the private key
    @Option(name: [.customShort("P"), .customLong("pin")], help: "PIN for private key access during signing")
    var pin: String?

    // CERTIFICATE VALIDITY: How long the certificate should be valid
    @Option(
        name: [.customShort("d"), .customLong("valid-days")],
        help: "Certificate validity period in days (default: 365)"
    )
    var validDays: Int = 365

    // HASH ALGORITHM: Hash algorithm for certificate signature (default: SHA256)
    @Option(
        name: [.customShort("a"), .customLong("hash-algorithm")],
        help: "Hash algorithm for signature (SHA256, SHA384, SHA512)"
    )
    var hashAlgorithm: String = "SHA256"

    func run() async throws {

        let slotValue = try ParameterValidator.validateSlot(slot)

        let session = try await PIVSession.shared()

        try await session.authenticate(with: managementKey)

        try await session.verifyPinIfProvided(pin)

        let metadata: PIV.SlotMetadata
        do {
            metadata = try await session.getMetadata(in: slotValue)
        } catch {
            throw PIVToolError.slotEmpty(slot: slot)
        }

        let algorithm = try ParameterValidator.validateHashAlgorithm(hashAlgorithm)

        // Create self-signed X.509 certificate using PIV private key for signing
        let certificate: X509Cert
        do {
            certificate = try await createSelfSignedCertificate(
                publicKey: metadata.publicKey,
                keyType: metadata.keyType,
                slot: slotValue,
                validDays: validDays,
                hashAlgorithm: algorithm,
                session: session
            )
        } catch {
            throw PIVToolError.generic("Failed to create certificate")
        }

        do {
            try await session.putCertificate(certificate, in: slotValue)

            // Print success message matching ykman format
            print("Certificate generated in slot \(slotValue.displayName).")
        } catch {
            throw PIVToolError.importFailed(reason: error.localizedDescription)
        }
    }
}

struct ExportCertificate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "export",
        abstract: "Export a certificate from a PIV slot"
    )

    // Exports certificate in PEM format (Base64-encoded with BEGIN/END markers)
    @Argument(help: "PIV slot containing certificate to export")
    var slot: String

    @Argument(help: "Output file for certificate (- for stdout, PEM format)")
    var output: String?

    func run() async throws {
        let slotValue = try ParameterValidator.validateSlot(slot)

        let session = try await PIVSession.shared()

        // Get certificate from slot
        let certificate: X509Cert
        do {
            certificate = try await session.getCertificate(in: slotValue)
        } catch {
            throw PIVToolError.certificateNotFound(slot: slot)
        }

        // Convert DER to PEM format using Exportable protocol
        let pemDocument = PEMDocument(type: "CERTIFICATE", derBytes: [UInt8](certificate.der))
        let pemString = pemDocument.pemString

        // Output to file or stdout
        if let output = output, output != "-" {
            do {
                try (pemString + "\n").write(toFile: output, atomically: true, encoding: .utf8)
            } catch {
                throw PIVToolError.fileWriteError(path: output, reason: error.localizedDescription)
            }
        } else {
            print(pemString)
        }
    }
}

struct RequestCertificate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "request",
        abstract: "Generate a Certificate Signing Request (CSR)"
    )

    // Creates a CSR that can be sent to a Certificate Authority (CA) for signing
    @Argument(help: "PIV slot containing private key for CSR signing")
    var slot: String

    @Argument(help: "Output file for CSR (- for stdout, PEM format)")
    var output: String

    @Option(name: [.customShort("P"), .customLong("pin")], help: "PIN for private key access during CSR signing")
    var pin: String?

    @Option(
        name: [.customShort("a"), .customLong("hash-algorithm")],
        help: "Hash algorithm for signature (SHA256, SHA384, SHA512)"
    )
    var hashAlgorithm: String = "SHA256"

    func run() async throws {
        let slotValue = try ParameterValidator.validateSlot(slot)

        let session = try await PIVSession.shared()

        try await session.verifyPinIfProvided(pin)

        // Get slot metadata to get the public key and key type
        let metadata: PIV.SlotMetadata
        do {
            metadata = try await session.getMetadata(in: slotValue)
        } catch {
            throw PIVToolError.slotEmpty(slot: slot)
        }

        let algorithm = try ParameterValidator.validateHashAlgorithm(hashAlgorithm)

        // Create CSR using helper function
        let csr: Data
        do {
            csr = try await createCertificateSigningRequest(
                publicKey: metadata.publicKey,
                keyType: metadata.keyType,
                slot: slotValue,
                hashAlgorithm: algorithm,
                session: session
            )
        } catch {
            throw PIVToolError.generic("Failed to create CSR: \(error.localizedDescription)")
        }

        // Convert to PEM format
        let pemDocument = PEMDocument(type: "CERTIFICATE REQUEST", derBytes: [UInt8](csr))
        let pemString = pemDocument.pemString

        // Output to file or stdout
        if output == "-" {
            print(pemString)
        } else {
            do {
                try (pemString + "\n").write(toFile: output, atomically: true, encoding: .utf8)
            } catch {
                throw PIVToolError.fileWriteError(path: output, reason: error.localizedDescription)
            }
        }
    }
}

struct ImportCertificate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "import",
        abstract: "Import an X.509 certificate into a PIV slot"
    )

    @Argument(help: "PIV slot to import certificate into")
    var slot: String

    @Argument(help: "Certificate file to import (PEM/DER format, - for stdin)")
    var certificate: String

    @Option(name: [.customShort("m"), .customLong("management-key")], help: "Management key")
    var managementKey: String?

    @Option(name: [.customShort("P"), .customLong("pin")], help: "PIN for authentication")
    var pin: String?

    func run() async throws {
        let slotValue = try ParameterValidator.validateSlot(slot)

        let session = try await PIVSession.shared()

        try await session.authenticate(with: managementKey)

        try await session.verifyPinIfProvided(pin)

        // Read certificate data
        let certData: Data
        if certificate == "-" {
            // Read from stdin
            certData = FileHandle.standardInput.readDataToEndOfFile()
        } else {
            // Read from file
            do {
                certData = try Data(contentsOf: URL(fileURLWithPath: certificate))
            } catch {
                throw PIVToolError.fileReadError(path: certificate, reason: error.localizedDescription)
            }
        }

        // Parse certificate (auto-detect PEM or DER format)
        let x509Cert: X509Cert
        // Try PEM first, fall back to DER
        if let pemString = String(data: certData, encoding: .utf8) {
            do {
                let pemDocument = try PEMDocument(pemString: pemString)
                x509Cert = X509Cert(der: Data(pemDocument.derBytes))
            } catch {
                x509Cert = X509Cert(der: certData)
            }
        } else {
            x509Cert = X509Cert(der: certData)
        }

        // Import certificate into slot
        do {
            try await session.putCertificate(x509Cert, in: slotValue)

            print("Certificate imported into slot \(slotValue.displayName).")
        } catch {
            throw PIVToolError.importFailed(reason: error.localizedDescription)
        }
    }
}

struct DeleteCertificate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "delete",
        abstract: "Delete a certificate from a PIV slot"
    )

    @Argument(help: "PIV slot to delete certificate from")
    var slot: String

    @Option(name: [.customShort("m"), .customLong("management-key")], help: "Management key")
    var managementKey: String?

    @Option(name: [.customShort("P"), .customLong("pin")], help: "PIN for authentication")
    var pin: String?

    func run() async throws {
        let slotValue = try ParameterValidator.validateSlot(slot)

        let session = try await PIVSession.shared()

        try await session.authenticate(with: managementKey)

        try await session.verifyPinIfProvided(pin)

        // Delete certificate from slot
        do {
            try await session.deleteCertificate(in: slotValue)

            print("Certificate deleted from slot \(slotValue.displayName).")
        }
    }
}
