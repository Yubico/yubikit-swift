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

    @Suite("CTAPHID")
    struct CTAPHID {

        #if os(macOS)
        @Test("CTAPHID interface initializes and reports a version and capabilities")
        func initialize() async throws { try await ScenarioTests.run(CTAPHIDScenario.initialize.scenario) }

        @Test("CTAPHID channel round-trips a CTAP2 getInfo")
        func getInfo() async throws { try await ScenarioTests.run(CTAPHIDScenario.getInfo.scenario) }

        @Test("CTAPHID capability flags report WINK support")
        func winkSupported() async throws { try await ScenarioTests.run(CTAPHIDScenario.winkSupported.scenario) }

        @Test("CTAPHID WINK command completes")
        func wink() async throws { try await ScenarioTests.run(CTAPHIDScenario.wink.scenario) }

        @Test("CTAPHID PING echoes empty and non-empty payloads")
        func echo() async throws { try await ScenarioTests.run(CTAPHIDScenario.echo.scenario) }

        @Test("an invalid CTAPHID command is rejected with a transport error")
        func invalidCommand() async throws { try await ScenarioTests.run(CTAPHIDScenario.invalidCommand.scenario) }
        #endif
    }
}
