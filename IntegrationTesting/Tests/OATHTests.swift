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

    @Suite("OATH")
    struct OATH {

        @Test("listCredentials returns the populated credentials with the expected labels and types")
        func credentials() async throws { try await ScenarioTests.run(OATHScenario.credentials.scenario) }

        @Test("calculateCredentialCodes plus manual touch/HOTP calculation yields the expected codes")
        func allCodes() async throws { try await ScenarioTests.run(OATHScenario.allCodes.scenario) }

        @Test("calculateCredentialCodes auto-calculates only the standard-period TOTP codes")
        func codes() async throws { try await ScenarioTests.run(OATHScenario.codes.scenario) }

        @Test("a credential whose issuer and name begin with digits can be added and calculated")
        func numericPrefixName() async throws { try await ScenarioTests.run(OATHScenario.numericPrefixName.scenario) }

        @Test("renameCredential updates the account name and issuer")
        func credentialRename() async throws { try await ScenarioTests.run(OATHScenario.credentialRename.scenario) }

        @Test("renameCredential can clear the issuer")
        func noIssuer() async throws { try await ScenarioTests.run(OATHScenario.noIssuer.scenario) }

        @Test("renaming a credential onto an existing identifier is rejected")
        func toExisting() async throws { try await ScenarioTests.run(OATHScenario.toExisting.scenario) }

        @Test("renaming onto a distinct existing credential's identifier is rejected")
        func toExistingDistinct() async throws { try await ScenarioTests.run(OATHScenario.toExistingDistinct.scenario) }

        @Test("deleteCredential removes a single credential")
        func credentialDelete() async throws { try await ScenarioTests.run(OATHScenario.credentialDelete.scenario) }

        @Test("a SHA-512 credential can be added and reports the SHA-512 algorithm")
        func sha512() async throws { try await ScenarioTests.run(OATHScenario.sha512.scenario) }

        @Test("a touch-required credential is reported as requiring touch and yields no auto code")
        func touch() async throws { try await ScenarioTests.run(OATHScenario.touch.scenario) }

        @Test("the OATH application resets and re-populates with the standard test accounts")
        func populatedReset() async throws { try await ScenarioTests.run(OATHScenario.populatedReset.scenario) }

        @Test("a password-protected application can be unlocked and listed")
        func unlock() async throws { try await ScenarioTests.run(OATHScenario.unlock.scenario) }

        @Test("unlocking with the wrong password fails with invalidPassword")
        func wrong() async throws { try await ScenarioTests.run(OATHScenario.wrong.scenario) }

        @Test("deleteAccessKey removes the password so a fresh session needs no unlock")
        func deleteAccessKey() async throws { try await ScenarioTests.run(OATHScenario.deleteAccessKey.scenario) }

        @Test("deleteAccessKey is rejected on a FIPS device")
        func deleteAccessKeyRejectedOnFIPS() async throws {
            try await ScenarioTests.run(OATHScenario.deleteAccessKeyRejectedOnFIPS.scenario)
        }

        @Test("a locked OATH application rejects listing until it is unlocked")
        func lockedListRejected() async throws { try await ScenarioTests.run(OATHScenario.lockedListRejected.scenario) }

        @Test("a locked OATH application rejects calculating a single code")
        func lockedCalculateRejected() async throws {
            try await ScenarioTests.run(OATHScenario.lockedCalculateRejected.scenario)
        }

        @Test("a locked OATH application rejects calculating all codes")
        func lockedCalculateAllRejected() async throws {
            try await ScenarioTests.run(OATHScenario.lockedCalculateAllRejected.scenario)
        }

        @Test("a locked OATH application rejects deleting a credential")
        func lockedDeleteRejected() async throws {
            try await ScenarioTests.run(OATHScenario.lockedDeleteRejected.scenario)
        }

        @Test("a locked OATH application rejects renaming a credential")
        func lockedRenameRejected() async throws {
            try await ScenarioTests.run(OATHScenario.lockedRenameRejected.scenario)
        }

        @Test("calculateCredentialResponse matches the RFC 2202 HMAC-SHA1 test vector")
        func response() async throws { try await ScenarioTests.run(OATHScenario.response.scenario) }

        @Test("the applet rejects adding beyond its credential limit")
        func maxCredentials() async throws { try await ScenarioTests.run(OATHScenario.maxCredentials.scenario) }

        @Test("a credential with a Unicode name round-trips correctly")
        func unicodeName() async throws { try await ScenarioTests.run(OATHScenario.unicodeName.scenario) }

        @Test(
            "RFC 4231 HMAC / 6238 TOTP / 4226 HOTP test-vector families",
            arguments: ScenarioTests.parameterizedFamilies(in: .oath, besides: OATHScenario.allCases.map(\.scenario))
        )
        func vectors(_ scenario: Scenario) async throws { try await ScenarioTests.run(scenario) }
    }
}
