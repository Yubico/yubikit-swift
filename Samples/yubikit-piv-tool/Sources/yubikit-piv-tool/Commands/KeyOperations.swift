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
import Darwin
import Foundation
import YubiKit

struct KeyOperation: ParsableArguments {
    @Argument(help: "PIV slot") var slot: String
    @Argument(help: "Input file (- for stdin)") var input: String
    @Argument(help: "Output file (- for binary stdout)") var output: String
    @Option(name: [.customShort("P"), .long], help: "PIN for private key access") var pin: String?
    @Option(name: .long, help: "Key algorithm for firmware before 5.3") var algorithm: String?

    func resolve(_ session: PIVSession) async throws -> (PIV.Slot, PIV.KeyType, PIV.PinPolicy) {
        let slot = try ParameterValidator.validateSlot(slot)
        let selected = try algorithm.map(ParameterValidator.validateKeyType)
        if await session.supports(PIVSessionFeature.metadata) {
            let metadata: PIV.SlotMetadata
            do { metadata = try await session.getMetadata(in: slot) } catch {
                throw pivError(error, missingDataMessage: "Slot \(self.slot) is empty.")
            }
            if let selected, selected != metadata.keyType {
                throw ToolError("--algorithm does not match the key in slot \(self.slot).")
            }
            return (slot, metadata.keyType, metadata.pinPolicy)
        }
        guard let selected else { throw ToolError("Slot metadata is unavailable; specify --algorithm.") }
        return (slot, selected, .defaultPolicy)
    }

    func authorize(_ session: PIVSession, policy: PIV.PinPolicy) async throws {
        var value = pin
        if value == nil, policy == .once || policy == .always {
            guard isatty(STDIN_FILENO) != 0, let entered = getpass("Enter PIN: ") else {
                throw ToolError("PIN required; provide --pin.")
            }
            value = String(cString: entered)
        }
        try await session.verifyPinIfProvided(value)
    }
}

struct Sign: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Sign an ML-DSA message")
    @OptionGroup var operation: KeyOperation
    @Option(name: [.customShort("a"), .long], help: "Not supported with ML-DSA") var hashAlgorithm: String?
    @Flag(name: .long, help: "Input is already a digest (not supported for ML-DSA)") var prehashed = false
    @Option(name: .long, help: "Not supported with ML-DSA") var padding: String?
    @Option(name: .long, help: "ML-DSA context string (at most 255 UTF-8 bytes)") var context: String?
    @Flag(name: .long, help: "Input is a precomputed 64-byte ML-DSA mu") var mu = false
    @Flag(name: .long, help: "Compute ML-DSA mu on the host (requires SDK support)") var computeMu = false

    func validate() throws {
        if mu && context != nil { throw ToolError("--context conflicts with --mu.") }
        if mu && computeMu { throw ToolError("--mu conflicts with --compute-mu.") }
        if let context, context.utf8.count > 255 { throw ToolError("--context must be at most 255 bytes.") }
        if hashAlgorithm != nil || prehashed || padding != nil {
            throw ToolError("ML-DSA signs messages directly; hash, prehashed and padding options are not supported.")
        }
    }

    func run() async throws {
        try validate()
        if computeMu {
            throw ToolError(
                "--compute-mu requires a host-mu API that this Swift SDK does not expose; supply a precomputed 64-byte value with --mu."
            )
        }
        let input = try CommandIO.read(operation.input)
        if mu && input.count != 64 { throw ToolError("ML-DSA mu input must be exactly 64 bytes.") }
        let session = try await PIVSession.shared()
        let (slot, type, policy) = try await operation.resolve(session)
        guard case .mlDSA(let parameters) = type else {
            throw ToolError("This sample's keys sign command requires an ML-DSA key.")
        }
        try await operation.authorize(session, policy: policy)
        let signature: Data
        do {
            if mu {
                signature = try await session.sign(externalMu: input, in: slot, keyType: .mlDSA(parameters))
            } else {
                signature = try await session.sign(
                    input,
                    in: slot,
                    keyType: .mlDSA(parameters),
                    context: Data((context ?? "").utf8)
                )
            }
        } catch { throw pivError(error) }
        try CommandIO.write(signature, to: operation.output)
    }
}

struct Decapsulate: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Decapsulate ML-KEM ciphertext and output the raw shared secret"
    )
    @OptionGroup var operation: KeyOperation

    func run() async throws {
        let input = try CommandIO.read(operation.input)
        if operation.output != "-", FileManager.default.fileExists(atPath: operation.output) {
            throw ToolError("Secret output must not already exist.")
        }
        let session = try await PIVSession.shared()
        let (slot, type, policy) = try await operation.resolve(session)
        guard case .mlKEM(let parameters) = type else { throw ToolError("Decapsulation requires an ML-KEM key.") }
        guard input.count == parameters.ciphertextByteCount else {
            throw ToolError("Invalid ML-KEM ciphertext length.")
        }
        try await operation.authorize(session, policy: policy)
        let secret: Data
        do { secret = try await session.decapsulate(input, in: slot, keyType: .mlKEM(parameters)) } catch {
            throw pivError(error)
        }
        guard secret.count == 32 else { throw ToolError("Invalid ML-KEM shared-secret length.") }
        try CommandIO.write(secret, to: operation.output, secret: true)
    }
}
