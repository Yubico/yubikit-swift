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

    @Suite("SCP")
    struct SCP {

        @Test("default SCP03 static keys authenticate a Management session")
        func defaultKeys() async throws { try await ScenarioTests.run(SCPScenario.defaultKeys.scenario) }

        @Test("Management.getDeviceInfo over an SCP03 secure channel")
        func managementDeviceInfo() async throws {
            try await ScenarioTests.run(SCPScenario.managementDeviceInfo.scenario)
        }

        @Test("importing a new SCP03 key set replaces the default keys")
        func importKeySCP03() async throws { try await ScenarioTests.run(SCPScenario.importKeySCP03.scenario) }

        @Test("deleting SCP03 keys (incl. the final key) revokes authentication")
        func deleteKey() async throws { try await ScenarioTests.run(SCPScenario.deleteKey.scenario) }

        @Test("replacing an SCP03 key revokes the old key version")
        func replaceKey() async throws { try await ScenarioTests.run(SCPScenario.replaceKey.scenario) }

        @Test("a wrong SCP03 key fails to authenticate and to send secure commands")
        func wrongKey() async throws { try await ScenarioTests.run(SCPScenario.wrongKey.scenario) }

        @Test("loads SCP11a keys over SCP03 then re-authenticates with SCP11a")
        func authenticateSCP11a() async throws { try await ScenarioTests.run(SCPScenario.authenticateSCP11a.scenario) }

        @Test("stores an OCE allow-list of valid serial numbers for SCP11a")
        func allowlist() async throws { try await ScenarioTests.run(SCPScenario.allowlist.scenario) }

        @Test("an allow-list of non-matching serials blocks SCP11a until cleared")
        func allowlistBlocked() async throws { try await ScenarioTests.run(SCPScenario.allowlistBlocked.scenario) }

        @Test("SCP11b reads the leaf certificate and gates unverified key generation")
        func authenticateSCP11b() async throws { try await ScenarioTests.run(SCPScenario.authenticateSCP11b.scenario) }

        @Test("SCP11b with the intermediate (wrong) public key fails to authenticate")
        func wrongPublicKey() async throws { try await ScenarioTests.run(SCPScenario.wrongPublicKey.scenario) }

        @Test("imports a generated SCP11b key pair and authenticates with it")
        func importKeySCP11b() async throws { try await ScenarioTests.run(SCPScenario.importKeySCP11b.scenario) }

        @Test("loads SCP11c keys over SCP03 and re-authenticates with SCP11c")
        func authenticateSCP11c() async throws { try await ScenarioTests.run(SCPScenario.authenticateSCP11c.scenario) }

        @Test("getKeyInformation returns the Security Domain key table")
        func keyInformation() async throws { try await ScenarioTests.run(SCPScenario.keyInformation.scenario) }

        @Test("getSupportedCAIdentifiers reports KLOC/KLCC identifiers")
        func supportedCAIdentifiers() async throws {
            try await ScenarioTests.run(SCPScenario.supportedCAIdentifiers.scenario)
        }

        @Test("getCertificateBundle yields a leaf key that authenticates SCP11b")
        func certificateBundle() async throws { try await ScenarioTests.run(SCPScenario.certificateBundle.scenario) }

        @Test("getCardRecognitionData reports the expected GlobalPlatform TLV tag sequence")
        func cardRecognitionData() async throws {
            try await ScenarioTests.run(SCPScenario.cardRecognitionData.scenario)
        }

        @Test("resetting the Security Domain restores the default SCP03 key set")
        func resetRestoresDefaultKeys() async throws {
            try await ScenarioTests.run(SCPScenario.resetRestoresDefaultKeys.scenario)
        }
    }
}
