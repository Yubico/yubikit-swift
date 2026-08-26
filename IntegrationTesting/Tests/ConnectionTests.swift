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

    @Suite("Connection")
    struct Connection {

        @Test("acquires a usable SmartCard connection")
        func open() async throws { try await ScenarioTests.run(ConnectionScenario.open.scenario) }

        @Test("waitUntilClosed() is notified with the closing error")
        func closeNotifies() async throws { try await ScenarioTests.run(ConnectionScenario.closeNotifies.scenario) }

        @Test("a second connection fails until the first is closed")
        func serial() async throws { try await ScenarioTests.run(ConnectionScenario.serial.scenario) }

        @Test("concurrent open attempts resolve to a single connection")
        func cancellation() async throws { try await ScenarioTests.run(ConnectionScenario.cancellation.scenario) }

        @Test("manual SELECT + device-info exchange reads the firmware version")
        func sendManually() async throws { try await ScenarioTests.run(ConnectionScenario.sendManually.scenario) }

        @Test("selecting a non-existent applet reports application-not-available")
        func selectWrongApp() async throws { try await ScenarioTests.run(ConnectionScenario.selectWrongApp.scenario) }

        @Test("opens a FIDO HID connection to an attached device")
        func withDeviceFIDOHID() async throws {
            try await ScenarioTests.run(ConnectionScenario.withDeviceFIDOHID.scenario)
        }

        #if os(iOS)
        @Test("the NFC reader alert message can be updated and the session closed with a message")
        func alertMessage() async throws { try await ScenarioTests.run(ConnectionScenario.alertMessage.scenario) }

        @Test("an NFC connection closes cleanly")
        func closingErrorMessage() async throws {
            try await ScenarioTests.run(ConnectionScenario.closingErrorMessage.scenario)
        }
        #endif
    }
}
