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
import SwiftASN1
import YubiKit

// MARK: - Key Management Commands

struct Keys: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "PIV key generation, information, and attestation operations",
        subcommands: [
            Generate.self,
            KeyInfo.self,
            Attest.self,
        ]
    )
}

struct Generate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate an asymmetric key pair"
    )

    @Argument(help: "PIV slot of the private key")
    var slot: String

    @Argument(help: "file containing the generated public key (use '-' to use stdout)")
    var publicKey: String

    @Option(
        name: [.customShort("a"), .customLong("algorithm")],
        help: "algorithm to use in key generation"
    )
    var algorithm: String = "RSA2048"

    @Option(
        name: [.customShort("m"), .customLong("management-key")],
        help: "the management key"
    )
    var managementKey: String?

    @Option(name: [.customShort("P"), .customLong("pin")], help: "PIN code")
    var pin: String?

    @Option(
        name: [.customShort("F"), .customLong("format")],
        help: "encoding format"
    )
    var format: String = "PEM"

    @Option(name: .long, help: "PIN policy for slot")
    var pinPolicy: String?

    @Option(name: .long, help: "touch policy for slot")
    var touchPolicy: String?

    func run() async throws {
        let slotValue = ParameterValidator.validateSlot(slot)

        let keyType: PIV.KeyType
        switch algorithm.uppercased() {
        case "RSA1024":
            keyType = .rsa(.bits1024)
        case "RSA2048":
            keyType = .rsa(.bits2048)
        case "RSA3072":
            keyType = .rsa(.bits3072)
        case "RSA4096":
            keyType = .rsa(.bits4096)
        case "ECCP256", "P256":
            keyType = .ecc(.secp256r1)
        case "ECCP384", "P384":
            keyType = .ecc(.secp384r1)
        case "ED25519":
            keyType = .ed25519
        case "X25519":
            keyType = .x25519
        default:
            exitWithError("Invalid key type: \(algorithm)")
        }

        let pinPol: PIV.PinPolicy
        if let pinPolicy = pinPolicy {
            switch pinPolicy.uppercased() {
            case "DEFAULT":
                pinPol = .defaultPolicy
            case "NEVER":
                pinPol = .never
            case "ONCE":
                pinPol = .once
            case "ALWAYS":
                pinPol = .always
            case "MATCH-ONCE":
                pinPol = .matchOnce
            case "MATCH-ALWAYS":
                pinPol = .matchAlways
            default:
                exitWithError(
                    "Invalid format for pin-policy.\n\tExpected: DEFAULT, NEVER, ONCE, ALWAYS, MATCH-ONCE, MATCH-ALWAYS.\n\tActual: \(pinPolicy)"
                )
            }
        } else {
            pinPol = .defaultPolicy
        }

        let touchPol: PIV.TouchPolicy
        if let touchPolicy = touchPolicy {
            switch touchPolicy.uppercased() {
            case "DEFAULT":
                touchPol = .defaultPolicy
            case "NEVER":
                touchPol = .never
            case "ALWAYS":
                touchPol = .always
            case "CACHED":
                touchPol = .cached
            default:
                exitWithError(
                    "Invalid format for touch-policy.\n\tExpected: DEFAULT, NEVER, ALWAYS, CACHED.\n\tActual: \(touchPolicy)"
                )
            }
        } else {
            touchPol = .defaultPolicy
        }

        let session = try await PIVSession.shared()

        // Authenticate with management key if provided
        if let managementKey = managementKey {
            await session.authenticate(with: managementKey)
        }

        // Verify PIN if provided
        if let pin = pin {
            do {
                let result = try await session.verifyPin(pin)
                switch result {
                case .success:
                    break
                case let .fail(retries):
                    exitWithError("PIN verification failed - \(retries) tries left.")
                case .pinLocked:
                    exitWithError("PIN is blocked.")
                }
            } catch {
                handlePIVError(error)
            }
        }

        // Generate asymmetric key pair on the YubiKey for the specified slot
        let generatedKey: PublicKey
        do {
            generatedKey = try await session.generateKey(
                in: slotValue,
                type: keyType,
                pinPolicy: pinPol,
                touchPolicy: touchPol
            )
        } catch {
            handlePIVError(error)
        }

        // Export public key in requested format (PEM or DER)
        switch format.uppercased() {
        case "PEM":
            // PEM format: Base64-encoded DER with BEGIN/END markers
            let pemString = generatedKey.pemRepresentation
            if publicKey != "-" {
                // Write to file
                do {
                    try pemString.write(toFile: publicKey, atomically: true, encoding: .utf8)
                } catch {
                    exitWithError("Failed to write file \(publicKey): \(error.localizedDescription)")
                }
            } else {
                // Write to stdout
                print(pemString, terminator: "")
            }

        case "DER":
            // SPKI DER
            let derData: Data
            switch generatedKey {
            case let .rsa(key):
                derData = key.der
            case let .ec(key):
                derData = key.der
            case let .ed25519(key):
                derData = key.der
            case let .x25519(key):
                derData = key.der
            }

            if publicKey != "-" {
                // Write binary to file
                do {
                    try derData.write(to: URL(fileURLWithPath: publicKey))
                } catch {
                    exitWithError("Failed to write file \(publicKey): \(error.localizedDescription)")
                }
            } else {
                // Write binary to stdout
                FileHandle.standardOutput.write(derData)
            }

        default:
            exitWithError("Invalid format for format.\n\tExpected: PEM, DER.\n\tActual: \(format)")
        }
    }
}

struct KeyInfo: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "info",
        abstract: "Display information about a key in the specified slot"
    )

    @Argument(help: "PIV slot to query for key information")
    var slot: String

    func run() async throws {
        let slotValue = ParameterValidator.validateSlot(slot)

        let session = try await PIVSession.shared()

        // Retrieve metadata about the key in the specified slot
        let metadata: PIV.SlotMetadata
        do {
            metadata = try await session.getMetadata(in: slotValue)
        } catch {
            exitWithError("Slot \(slot) is empty.")
        }

        print("Algorithm: \(algorithmName(for: metadata.keyType))")
        print("Origin: \(metadata.generated ? "Generated" : "Imported")")
        print("PIN policy: \(policyName(for: metadata.pinPolicy))")
        print("Touch policy: \(policyName(for: metadata.touchPolicy))")
    }

    private func algorithmName(for keyType: PIV.KeyType) -> String {
        switch keyType {
        case let .rsa(keySize):
            return "RSA\(keySize.bitCount)"
        case .ecc(.secp256r1):
            return "ECCP256"
        case .ecc(.secp384r1):
            return "ECCP384"
        case .ed25519:
            return "Ed25519"
        case .x25519:
            return "X25519"
        }
    }

    private func policyName(for policy: PIV.PinPolicy) -> String {
        switch policy {
        case .defaultPolicy:
            return "Default"
        case .never:
            return "Never"
        case .once:
            return "Once"
        case .always:
            return "Always"
        case .matchOnce:
            return "Match once"
        case .matchAlways:
            return "Match always"
        }
    }

    private func policyName(for policy: PIV.TouchPolicy) -> String {
        switch policy {
        case .defaultPolicy:
            return "Default"
        case .never:
            return "Never"
        case .always:
            return "Always"
        case .cached:
            return "Cached"
        }
    }
}

struct Attest: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Generate an attestation certificate for a key"
    )

    @Argument(help: "PIV slot containing key to attest (key must be generated on the YubiKey)")
    var slot: String

    @Argument(help: "Output file for attestation certificate (proves hardware key generation)")
    var output: String?

    func run() async throws {
        let slotValue = ParameterValidator.validateSlot(slot)

        let session = try await PIVSession.shared()

        // Generate hardware attestation certificate for the key
        let attestationCert: X509Cert
        do {
            attestationCert = try await session.attestKey(in: slotValue)
        } catch {
            exitWithError("Attestation not supported for slot \(slot).")
        }

        // Convert attestation certificate to PEM format
        let pemDocument = PEMDocument(type: "CERTIFICATE", derBytes: [UInt8](attestationCert.der))
        let pemString = pemDocument.pemString

        // Output attestation certificate to file or stdout
        if let output = output {
            do {
                try (pemString + "\n").write(toFile: output, atomically: true, encoding: .utf8)
            } catch {
                exitWithError("Failed to write file \(output): \(error.localizedDescription)")
            }
        } else {
            print(pemString)
        }
    }
}
