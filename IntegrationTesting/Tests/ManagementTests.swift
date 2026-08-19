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

    @Suite("Management")
    struct Management {

        @Test("reports a firmware version")
        func version() async throws { try await ScenarioTests.run(ManagementScenario.version.scenario) }

        @Test("getDeviceInfo round-trips with a serial number")
        func deviceInfo() async throws { try await ScenarioTests.run(ManagementScenario.deviceInfo.scenario) }

        @Test("updateDeviceConfig round-trips auto-eject / challenge-response timeouts")
        func timeouts() async throws { try await ScenarioTests.run(ManagementScenario.timeouts.scenario) }

        @Test("chained enable/disable across applications round-trips")
        func chaining() async throws { try await ScenarioTests.run(ManagementScenario.chaining.scenario) }

        @Test("a disabled application can no longer be selected (then re-enabled)")
        func disableEnableApplication() async throws {
            try await ScenarioTests.run(ManagementScenario.disableEnableApplication.scenario)
        }

        @Test("a set lock code is required to change configuration")
        func lockCode() async throws { try await ScenarioTests.run(ManagementScenario.lockCode.scenario) }

        @Test("NFC can be restricted until next USB insertion")
        func nfcRestricted() async throws { try await ScenarioTests.run(ManagementScenario.nfcRestricted.scenario) }

        @Test("device-wide reset restores the default PIV PIN (Bio MPE)")
        func bioDeviceReset() async throws { try await ScenarioTests.run(ManagementScenario.bioDeviceReset.scenario) }
    }
}
