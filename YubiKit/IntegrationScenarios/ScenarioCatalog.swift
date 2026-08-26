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

import Foundation

extension Scenario {

    public enum Catalog {

        public static let allDeclared: [Scenario] = {
            var scenarios: [Scenario] = []
            scenarios += ManagementScenario.allCases.map(\.scenario)
            scenarios += PIVScenario.allCases.map(\.scenario)
            scenarios += OATHScenario.allCases.map(\.scenario)
            scenarios += ConnectionScenario.allCases.map(\.scenario)
            scenarios += CTAP2Scenario.allCases.map(\.scenario)
            scenarios += CTAPHIDScenario.allCases.map(\.scenario)
            scenarios += WebAuthnScenario.allCases.map(\.scenario)
            scenarios += SCPScenario.allCases.map(\.scenario)
            return scenarios
        }()

        public static let all: [Scenario] = allDeclared.filter { $0.platform.runsHere }

        public static let suites: [Scenario.Suite] =
            Scenario.Suite.allCases.filter { suite in all.contains { $0.suite == suite } }

        public static func scenarios(in suite: Scenario.Suite) -> [Scenario] {
            all.filter { $0.suite == suite }
        }
    }
}
