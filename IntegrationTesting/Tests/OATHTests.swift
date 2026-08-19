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

        @Test("calculateCredentialCodes reassembles a response that spans multiple frames")
        func chunkedData() async throws { try await ScenarioTests.run(OATHScenario.chunkedData.scenario) }

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

        @Test("a locked OATH application rejects listing until it is unlocked")
        func lockedListRejected() async throws { try await ScenarioTests.run(OATHScenario.lockedListRejected.scenario) }

        @Test("calculateCredentialResponse matches the RFC 2202 HMAC-SHA1 test vector")
        func response() async throws { try await ScenarioTests.run(OATHScenario.response.scenario) }

        @Test("calculateCredentialResponse matches the RFC 4231 HMAC-SHA256 vector")
        func hmacSha256() async throws { try await ScenarioTests.run(OATHScenario.hmacSha256.scenario) }

        @Test("calculateCredentialResponse matches the RFC 4231 HMAC-SHA512 vector")
        func hmacSha512() async throws { try await ScenarioTests.run(OATHScenario.hmacSha512.scenario) }

        @Test("calculateCredentialCode matches the RFC 6238 TOTP-SHA1 vector at t=59")
        func totpSha1_59() async throws { try await ScenarioTests.run(OATHScenario.totpSha1_59.scenario) }

        @Test("successive calculateCredentialCode calls match the RFC 4226 HOTP-SHA1 vectors")
        func hotpSha1() async throws { try await ScenarioTests.run(OATHScenario.hotpSha1.scenario) }
    }
}
