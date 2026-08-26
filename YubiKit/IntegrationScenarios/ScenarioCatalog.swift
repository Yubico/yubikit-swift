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

/// A scenario suite: enumerated cases plus any parameterized families. Every suite enum conforms,
/// so the catalog collects them uniformly through `allScenarios`.
protocol ScenarioSuite: CaseIterable {
    var scenario: Scenario { get }
    /// Parameterized families fanned out from a base definition (default: none).
    static var parameterizedScenarios: [Scenario] { get }
}

extension ScenarioSuite {
    static var parameterizedScenarios: [Scenario] { [] }
    /// One scenario per enumerated case, followed by any parameterized families.
    static var allScenarios: [Scenario] { allCases.map(\.scenario) + parameterizedScenarios }
}

extension Scenario {

    public enum Catalog {

        public static let allDeclared: [Scenario] = {
            var scenarios: [Scenario] = []
            scenarios += ManagementScenario.allScenarios
            scenarios += PIVScenario.allScenarios
            scenarios += OATHScenario.allScenarios
            scenarios += ConnectionScenario.allScenarios
            scenarios += CTAP2Scenario.allScenarios
            scenarios += CTAPHIDScenario.allScenarios
            scenarios += WebAuthnScenario.allScenarios
            scenarios += SCPScenario.allScenarios
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
