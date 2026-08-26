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

    @Suite("WebAuthn")
    struct WebAuthn {

        @Test("makeCredential then getAssertion round-trips a discoverable credential")
        func makeCredentialGetAssertion() async throws {
            try await ScenarioTests.run(WebAuthnScenario.makeCredentialGetAssertion.scenario)
        }

        @Test("getAssertion honors a matching allow-list entry")
        func allowCredentials() async throws { try await ScenarioTests.run(WebAuthnScenario.allowCredentials.scenario) }

        @Test("getAssertion with an unknown allow-list entry throws noCredentials")
        func allowListNoMatch() async throws { try await ScenarioTests.run(WebAuthnScenario.allowListNoMatch.scenario) }

        @Test("makeCredential rejects a credential already in the exclude list")
        func excludeCredentials() async throws {
            try await ScenarioTests.run(WebAuthnScenario.excludeCredentials.scenario)
        }

        @Test("getAssertion returns one match per discoverable credential for selection")
        func multipleCredentialsCeremony() async throws {
            try await ScenarioTests.run(WebAuthnScenario.multipleCredentialsCeremony.scenario)
        }

        @Test("makeCredential rejects an RP ID that doesn't match the origin")
        func rpIdMismatch() async throws { try await ScenarioTests.run(WebAuthnScenario.rpIdMismatch.scenario) }

        @Test("makeCredential rejects an RP ID that is a public suffix")
        func publicSuffixRejected() async throws {
            try await ScenarioTests.run(WebAuthnScenario.publicSuffixRejected.scenario)
        }

        @Test("makeCredential with the wrong PIN throws pinRejected and decrements retries")
        func wrongPin() async throws { try await ScenarioTests.run(WebAuthnScenario.wrongPin.scenario) }

        @Test("clientDataJSON serializes with spec key ordering")
        func clientDataJSON() async throws { try await ScenarioTests.run(WebAuthnScenario.clientDataJSON.scenario) }

        @Test("getAssertion status stream delivers user-presence events and pulls the PIN via closure")
        func statusStream() async throws { try await ScenarioTests.run(WebAuthnScenario.statusStream.scenario) }

        @Test("discoverable getAssertion for an RP with no credentials throws noCredentials")
        func discoverableNoCredentials() async throws {
            try await ScenarioTests.run(WebAuthnScenario.discoverableNoCredentials.scenario)
        }

        @Test("makeCredential consumes a pre-supplied PIN silently while still emitting waitingForUser")
        func prefetchedPinMakeCredential() async throws {
            try await ScenarioTests.run(WebAuthnScenario.prefetchedPinMakeCredential.scenario)
        }

        @Test("getAssertion consumes a pre-supplied PIN silently")
        func prefetchedPinGetAssertion() async throws {
            try await ScenarioTests.run(WebAuthnScenario.prefetchedPinGetAssertion.scenario)
        }

        @Test("makeCredential can be cancelled from the status stream")
        func cancelMakeCredential() async throws {
            try await ScenarioTests.run(WebAuthnScenario.cancelMakeCredential.scenario)
        }

        @Test("credProtect echoes the applied protection level for each policy")
        func allLevels() async throws { try await ScenarioTests.run(WebAuthnScenario.allLevels.scenario) }

        @Test("PRF enabled at registration derives deterministic secrets at authentication")
        func derive() async throws { try await ScenarioTests.run(WebAuthnScenario.derive.scenario) }

        @Test("PRF derives secrets at registration (hmac-secret-mc) deterministically")
        func makeCredential() async throws { try await ScenarioTests.run(WebAuthnScenario.makeCredential.scenario) }

        @Test("largeBlob stores and retrieves data, then deletes it via CTAP")
        func storeRetrieveLargeBlob() async throws {
            try await ScenarioTests.run(WebAuthnScenario.storeRetrieveLargeBlob.scenario)
        }

        @Test("largeBlob keeps independent blobs per credential")
        func multipleCredentialsLargeBlob() async throws {
            try await ScenarioTests.run(WebAuthnScenario.multipleCredentialsLargeBlob.scenario)
        }

        @Test("largeBlob write rejects an oversized blob with storageFull")
        func storageFull() async throws { try await ScenarioTests.run(WebAuthnScenario.storageFull.scenario) }

        @Test("credBlob stored at registration is retrieved at authentication")
        func storeRetrieveCredBlob() async throws {
            try await ScenarioTests.run(WebAuthnScenario.storeRetrieveCredBlob.scenario)
        }

        @Test("credBlob is not returned when not requested at authentication")
        func notReturnedWithoutExtension() async throws {
            try await ScenarioTests.run(WebAuthnScenario.notReturnedWithoutExtension.scenario)
        }

        @Test("credBlob exceeding maxCredBlobLength is rejected")
        func oversizedRejected() async throws {
            try await ScenarioTests.run(WebAuthnScenario.oversizedRejected.scenario)
        }

        @Test("credProps reports rk=true for a discoverable credential")
        func discoverable() async throws { try await ScenarioTests.run(WebAuthnScenario.discoverable.scenario) }

        @Test("credProps reports rk=false for a non-discoverable credential")
        func nonDiscoverable() async throws { try await ScenarioTests.run(WebAuthnScenario.nonDiscoverable.scenario) }

        @Test("credProps is nil when not requested")
        func notRequested() async throws { try await ScenarioTests.run(WebAuthnScenario.notRequested.scenario) }

        @Test("minPinLength returns the enforced length once the RP is configured")
        func returnsValue() async throws { try await ScenarioTests.run(WebAuthnScenario.returnsValue.scenario) }

        @Test("previewSign produces no output when no input is supplied")
        func noOutputWithoutInput() async throws {
            try await ScenarioTests.run(WebAuthnScenario.noOutputWithoutInput.scenario)
        }

        @Test("previewSign generateKey returns a key handle, public key, and attestation")
        func generateKey() async throws { try await ScenarioTests.run(WebAuthnScenario.generateKey.scenario) }

        @Test("thirdPartyPayment echoes false when the credential isn't registered for payment")
        func echoedFalse() async throws { try await ScenarioTests.run(WebAuthnScenario.echoedFalse.scenario) }

        @Test("thirdPartyPayment echoes true when the credential is registered for payment")
        func echoedTrue() async throws { try await ScenarioTests.run(WebAuthnScenario.echoedTrue.scenario) }
    }
}
