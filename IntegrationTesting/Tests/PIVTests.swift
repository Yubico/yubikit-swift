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

import Testing
import YubiKitIntegrationScenarios

extension ScenarioSuites {

    @Suite("PIV")
    struct PIV {

        @Test("signs a message with an ECC P-256 key (ECDSA SHA-256)")
        func eccp256Message() async throws { try await ScenarioTests.run(PIVScenario.eccp256Message.scenario) }

        @Test("signs a pre-hashed digest with an ECC P-256 key")
        func eccp256Digest() async throws { try await ScenarioTests.run(PIVScenario.eccp256Digest.scenario) }

        @Test("signs a message with an RSA-1024 key (PKCS#1 v1.5 SHA-512)")
        func rsa1024Signatures() async throws { try await ScenarioTests.run(PIVScenario.rsa1024Signatures.scenario) }

        @Test("signs a message with an RSA-2048 key (PKCS#1 v1.5 SHA-512)")
        func rsa2048Signatures() async throws { try await ScenarioTests.run(PIVScenario.rsa2048Signatures.scenario) }

        @Test("signs a message with an Ed25519 key")
        func ed25519Signatures() async throws { try await ScenarioTests.run(PIVScenario.ed25519Signatures.scenario) }

        @Test("decrypts with a generated RSA-1024 key (PKCS#1 v1.5)")
        func rsa1024Decryption() async throws { try await ScenarioTests.run(PIVScenario.rsa1024Decryption.scenario) }

        @Test("decrypts with a generated RSA-2048 key (PKCS#1 v1.5)")
        func rsa2048Decryption() async throws { try await ScenarioTests.run(PIVScenario.rsa2048Decryption.scenario) }

        @Test("computes an ECDH shared secret with P-256 matching software ECDH")
        func ecdhP256() async throws { try await ScenarioTests.run(PIVScenario.ecdhP256.scenario) }

        @Test("computes an ECDH shared secret with P-384 matching software ECDH")
        func ecdhP384() async throws { try await ScenarioTests.run(PIVScenario.ecdhP384.scenario) }

        @Test("computes an X25519 shared secret matching software ECDH")
        func x25519KeyAgreement() async throws { try await ScenarioTests.run(PIVScenario.x25519KeyAgreement.scenario) }

        @Test("imports an RSA-1024 key and decrypts with it")
        func rsa1024KeyImport() async throws { try await ScenarioTests.run(PIVScenario.rsa1024KeyImport.scenario) }

        @Test("imports an RSA-2048 key and decrypts with it")
        func rsa2048KeyImport() async throws { try await ScenarioTests.run(PIVScenario.rsa2048KeyImport.scenario) }

        @Test("imports an RSA-3072 key and decrypts with it")
        func rsa3072KeyImport() async throws { try await ScenarioTests.run(PIVScenario.rsa3072KeyImport.scenario) }

        @Test("imports an RSA-4096 key and decrypts with it")
        func rsa4096KeyImport() async throws { try await ScenarioTests.run(PIVScenario.rsa4096KeyImport.scenario) }

        @Test("imports an EC P-256 key and signs with it")
        func eccp256KeyImport() async throws { try await ScenarioTests.run(PIVScenario.eccp256KeyImport.scenario) }

        @Test("imports an EC P-384 key and signs with it")
        func eccp384KeyImport() async throws { try await ScenarioTests.run(PIVScenario.eccp384KeyImport.scenario) }

        @Test("imports an Ed25519 key and signs with it")
        func ed25519KeyImport() async throws { try await ScenarioTests.run(PIVScenario.ed25519KeyImport.scenario) }

        @Test("imports an X25519 key and performs key agreement")
        func x25519KeyImport() async throws { try await ScenarioTests.run(PIVScenario.x25519KeyImport.scenario) }

        @Test("generates an RSA-1024 key")
        func rsa1024KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.rsa1024KeyGeneration.scenario)
        }

        @Test("generates an RSA-2048 key")
        func rsa2048KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.rsa2048KeyGeneration.scenario)
        }

        @Test("generates an RSA-3072 key")
        func rsa3072KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.rsa3072KeyGeneration.scenario)
        }

        @Test("generates an RSA-4096 key")
        func rsa4096KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.rsa4096KeyGeneration.scenario)
        }

        @Test("generates an EC P-256 key")
        func eccp256KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.eccp256KeyGeneration.scenario)
        }

        @Test("generates an EC P-384 key")
        func eccp384KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.eccp384KeyGeneration.scenario)
        }

        @Test("generates an Ed25519 key")
        func ed25519KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.ed25519KeyGeneration.scenario)
        }

        @Test("generates an X25519 key")
        func x25519KeyGeneration() async throws {
            try await ScenarioTests.run(PIVScenario.x25519KeyGeneration.scenario)
        }

        @Test("attests a generated RSA key")
        func rsa() async throws { try await ScenarioTests.run(PIVScenario.rsa.scenario) }

        @Test("attests a generated Ed25519 key")
        func ed25519Attestation() async throws { try await ScenarioTests.run(PIVScenario.ed25519Attestation.scenario) }

        @Test("attests a generated X25519 key")
        func x25519Attestation() async throws { try await ScenarioTests.run(PIVScenario.x25519Attestation.scenario) }

        @Test("writes and reads back an X.509 certificate")
        func putGet() async throws { try await ScenarioTests.run(PIVScenario.putGet.scenario) }

        @Test("writes a compressed certificate and reads it back decompressed")
        func putCompressedGet() async throws { try await ScenarioTests.run(PIVScenario.putCompressedGet.scenario) }

        @Test("deletes a stored certificate")
        func putDelete() async throws { try await ScenarioTests.run(PIVScenario.putDelete.scenario) }

        @Test("reads a stored certificate from a fresh, unauthenticated session")
        func getWithoutAuth() async throws { try await ScenarioTests.run(PIVScenario.getWithoutAuth.scenario) }

        @Test("moves a key from one slot to another")
        func move() async throws { try await ScenarioTests.run(PIVScenario.move.scenario) }

        @Test("deletes a key from a slot")
        func delete() async throws { try await ScenarioTests.run(PIVScenario.delete.scenario) }

        @Test("authenticates with the default management key")
        func authenticateDefault() async throws {
            try await ScenarioTests.run(PIVScenario.authenticateDefault.scenario)
        }

        @Test("rejects a wrong management key")
        func authenticateWrong() async throws { try await ScenarioTests.run(PIVScenario.authenticateWrong.scenario) }

        @Test("a changed management key authenticates and the old key no longer does")
        func changeAndReauthenticate() async throws {
            try await ScenarioTests.run(PIVScenario.changeAndReauthenticate.scenario)
        }

        @Test("verifies the default PIN and resets the retry counter")
        func verify() async throws { try await ScenarioTests.run(PIVScenario.verify.scenario) }

        @Test("decrements and then locks the PIN retry counter")
        func verifyRetryCount() async throws { try await ScenarioTests.run(PIVScenario.verifyRetryCount.scenario) }

        @Test("sets the PIN and PUK retry attempts")
        func setAttempts() async throws { try await ScenarioTests.run(PIVScenario.setAttempts.scenario) }

        @Test("reports remaining retries when changing the PIN with a wrong old PIN")
        func changePinFailure() async throws { try await ScenarioTests.run(PIVScenario.changePinFailure.scenario) }

        @Test("changes the PIN and verifies with the new value")
        func changePinSuccess() async throws { try await ScenarioTests.run(PIVScenario.changePinSuccess.scenario) }

        @Test("unblocks a blocked PIN with the PUK")
        func unblock() async throws { try await ScenarioTests.run(PIVScenario.unblock.scenario) }

        @Test("changes the PUK and uses it to unblock the PIN")
        func changePukUnblock() async throws { try await ScenarioTests.run(PIVScenario.changePukUnblock.scenario) }

        @Test("unblocking the PIN with a wrong PUK reports invalidPin with one retry consumed")
        func unblockWrongPuk() async throws { try await ScenarioTests.run(PIVScenario.unblockWrongPuk.scenario) }

        @Test("a key with PIN policy ALWAYS requires a fresh PIN verification before every signature")
        func pinPolicyAlways() async throws { try await ScenarioTests.run(PIVScenario.pinPolicyAlways.scenario) }

        @Test("reports a firmware version")
        func version() async throws { try await ScenarioTests.run(PIVScenario.version.scenario) }

        @Test("reports a serial number")
        func serialNumber() async throws { try await ScenarioTests.run(PIVScenario.serialNumber.scenario) }

        @Test("reads default management key metadata")
        func managementKey() async throws { try await ScenarioTests.run(PIVScenario.managementKey.scenario) }

        @Test("reads slot metadata for generated keys across PIN/touch policies")
        func slot() async throws { try await ScenarioTests.run(PIVScenario.slot.scenario) }

        @Test("reads metadata after setting an AES-192 management key")
        func aesManagementKey() async throws { try await ScenarioTests.run(PIVScenario.aesManagementKey.scenario) }

        @Test("reads default PIN metadata")
        func pin() async throws { try await ScenarioTests.run(PIVScenario.pin.scenario) }

        @Test("reflects a consumed retry in PIN metadata")
        func pinRetries() async throws { try await ScenarioTests.run(PIVScenario.pinRetries.scenario) }

        @Test("reads default PUK metadata")
        func puk() async throws { try await ScenarioTests.run(PIVScenario.puk.scenario) }

        @Test("authenticates with biometrics and a temporary PIN (YubiKey Bio)")
        func authentication() async throws { try await ScenarioTests.run(PIVScenario.authentication.scenario) }

        @Test("rejects match PIN policies on a non-Bio YubiKey")
        func pinPolicyErrorNonBio() async throws {
            try await ScenarioTests.run(PIVScenario.pinPolicyErrorNonBio.scenario)
        }

        @Test("verifyUV is rejected on a Bio device with no fingerprints enrolled")
        func verifyUvWithoutFingerprints() async throws {
            try await ScenarioTests.run(PIVScenario.verifyUvWithoutFingerprints.scenario)
        }
    }
}
