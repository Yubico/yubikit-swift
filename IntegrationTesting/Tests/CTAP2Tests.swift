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

    @Suite("CTAP2")
    struct CTAP2 {

        @Test("getInfo reports recognized FIDO versions and options")
        func getInfo() async throws { try await ScenarioTests.run(CTAP2Scenario.getInfo.scenario) }

        @Test("makeCredential then getAssertion (by allow-list) round-trips a signature")
        func makeGetAllowList() async throws { try await ScenarioTests.run(CTAP2Scenario.makeGetAllowList.scenario) }

        @Test("non-resident + resident makeCredential, then getAssertion by RK discovery")
        func makeGetDiscoverable() async throws {
            try await ScenarioTests.run(CTAP2Scenario.makeGetDiscoverable.scenario)
        }

        @Test("makeCredential with ES256 returns an ES256 credential key")
        func makeES256() async throws { try await ScenarioTests.run(CTAP2Scenario.makeES256.scenario) }

        @Test("makeCredential with EdDSA returns an Ed25519 credential key")
        func makeEdDSA() async throws { try await ScenarioTests.run(CTAP2Scenario.makeEdDSA.scenario) }

        @Test("makeCredential with ES384 returns an ES384 credential key")
        func makeES384() async throws { try await ScenarioTests.run(CTAP2Scenario.makeES384.scenario) }

        @Test("makeCredential can be cancelled while waiting for user presence")
        func cancelMakeCredential() async throws {
            try await ScenarioTests.run(CTAP2Scenario.cancelMakeCredential.scenario)
        }

        @Test("EdDSA and ES384 assertions verify against the returned credential public key")
        func algorithmSignatureVerify() async throws {
            try await ScenarioTests.run(CTAP2Scenario.algorithmSignatureVerify.scenario)
        }

        @Test("two resident credentials for one RP yield multiple assertions via getNextAssertion")
        func getNextAssertion() async throws { try await ScenarioTests.run(CTAP2Scenario.getNextAssertion.scenario) }

        @Test("getAssertion with up=false clears the user-presence flag")
        func upFalseClearsFlag() async throws { try await ScenarioTests.run(CTAP2Scenario.upFalseClearsFlag.scenario) }

        @Test("clientPIN setup: set the PIN and reset the retry counter (V1)")
        func setupV1() async throws { try await ScenarioTests.run(CTAP2Scenario.setupV1.scenario) }

        @Test("clientPIN change PIN and verify the retry counter (V1)")
        func changePinV1() async throws { try await ScenarioTests.run(CTAP2Scenario.changePinV1.scenario) }

        @Test("clientPIN get token using built-in UV (V1)")
        func tokenUsingUvV1() async throws { try await ScenarioTests.run(CTAP2Scenario.tokenUsingUvV1.scenario) }

        @Test("clientPIN complexity enforcement rejects weak PINs (V1)")
        func complexityV1() async throws { try await ScenarioTests.run(CTAP2Scenario.complexityV1.scenario) }

        @Test("clientPIN retry exhaustion soft-locks the authenticator (V1)")
        func retryExhaustionV1() async throws { try await ScenarioTests.run(CTAP2Scenario.retryExhaustionV1.scenario) }

        @Test("clientPIN setup: set the PIN and reset the retry counter (V2)")
        func setupV2() async throws { try await ScenarioTests.run(CTAP2Scenario.setupV2.scenario) }

        @Test("clientPIN change PIN and verify the retry counter (V2)")
        func changePinV2() async throws { try await ScenarioTests.run(CTAP2Scenario.changePinV2.scenario) }

        @Test("clientPIN get token using built-in UV (V2)")
        func tokenUsingUvV2() async throws { try await ScenarioTests.run(CTAP2Scenario.tokenUsingUvV2.scenario) }

        @Test("clientPIN complexity enforcement rejects weak PINs (V2)")
        func complexityV2() async throws { try await ScenarioTests.run(CTAP2Scenario.complexityV2.scenario) }

        @Test("clientPIN retry exhaustion soft-locks the authenticator (V2)")
        func retryExhaustionV2() async throws { try await ScenarioTests.run(CTAP2Scenario.retryExhaustionV2.scenario) }

        @Test("operations return empty results when no credentials exist")
        func emptyState() async throws { try await ScenarioTests.run(CTAP2Scenario.emptyState.scenario) }

        @Test("getMetadata reports one stored credential")
        func metadata() async throws { try await ScenarioTests.run(CTAP2Scenario.metadata.scenario) }

        @Test("enumerate RPs and their credentials")
        func enumerate() async throws { try await ScenarioTests.run(CTAP2Scenario.enumerate.scenario) }

        @Test("delete a credential")
        func delete() async throws { try await ScenarioTests.run(CTAP2Scenario.delete.scenario) }

        @Test("update the user information on a credential")
        func updateUserInfo() async throws { try await ScenarioTests.run(CTAP2Scenario.updateUserInfo.scenario) }

        @Test("read-only credential management with a persistent pinUvAuthToken")
        func readOnlyPpuat() async throws { try await ScenarioTests.run(CTAP2Scenario.readOnlyPpuat.scenario) }

        @Test("authenticatorConfig support check")
        func support() async throws { try await ScenarioTests.run(CTAP2Scenario.support.scenario) }

        @Test("toggle the alwaysUV setting and restore it")
        func toggleAlwaysUv() async throws { try await ScenarioTests.run(CTAP2Scenario.toggleAlwaysUv.scenario) }

        @Test("enable enterprise attestation")
        func enableEnterpriseAttestation() async throws {
            try await ScenarioTests.run(CTAP2Scenario.enableEnterpriseAttestation.scenario)
        }

        @Test("set the force-PIN-change flag")
        func setForcePinChange() async throws { try await ScenarioTests.run(CTAP2Scenario.setForcePinChange.scenario) }

        @Test("increase the minimum PIN length and reject a decrease")
        func setMinPinLength() async throws { try await ScenarioTests.run(CTAP2Scenario.setMinPinLength.scenario) }

        @Test("with alwaysUV enabled, makeCredential without UV is rejected and with UV succeeds")
        func alwaysUvEnforced() async throws { try await ScenarioTests.run(CTAP2Scenario.alwaysUvEnforced.scenario) }

        @Test("decrypt encIdentifier with a persistent pinUvAuthToken")
        func decryptIdentifier() async throws { try await ScenarioTests.run(CTAP2Scenario.decryptIdentifier.scenario) }

        @Test("decrypt encCredStoreState with a persistent pinUvAuthToken")
        func decryptCredStoreState() async throws {
            try await ScenarioTests.run(CTAP2Scenario.decryptCredStoreState.scenario)
        }

        @Test("a persistent pinUvAuthToken decrypts the same values across re-establishment")
        func persistentToken() async throws { try await ScenarioTests.run(CTAP2Scenario.persistentToken.scenario) }

        @Test("credStoreState changes when credentials are added or deleted")
        func credStoreStateChanges() async throws {
            try await ScenarioTests.run(CTAP2Scenario.credStoreStateChanges.scenario)
        }

        @Test("read the fingerprint sensor info")
        func sensorInfo() async throws { try await ScenarioTests.run(CTAP2Scenario.sensorInfo.scenario) }

        @Test("enroll, rename, and delete a fingerprint")
        func enrollRenameDelete() async throws {
            try await ScenarioTests.run(CTAP2Scenario.enrollRenameDelete.scenario)
        }

        @Test("create a credential using a fingerprint UV token (UP + UV flags)")
        func makeCredentialUvToken() async throws {
            try await ScenarioTests.run(CTAP2Scenario.makeCredentialUvToken.scenario)
        }

        @Test("UV blocks after repeated wrong fingerprints, then PIN still works")
        func uvBlocking() async throws { try await ScenarioTests.run(CTAP2Scenario.uvBlocking.scenario) }

        @Test("selection performs a user-presence check")
        func userPresence() async throws { try await ScenarioTests.run(CTAP2Scenario.userPresence.scenario) }

        @Test("factory reset clears credentials and the PIN")
        func factory() async throws { try await ScenarioTests.run(CTAP2Scenario.factory.scenario) }
    }
}
