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

/// One value in a parameterized scenario family. It carries the per-case metadata (id suffix,
/// display name, gating) so `Scenario.parameterized` needs only a single body closure — the moral
/// equivalent of a row in pytest's `@pytest.mark.parametrize`.
protocol ScenarioParameter: Sendable {
    /// Appended to the family id to keep each case's id unique (e.g. `"tc1.sha256"`).
    var idSuffix: String { get }
    /// Per-case display name.
    var displayName: String { get }
    /// Per-case gating (a SHA-512 vector can require newer firmware than its SHA-256 sibling).
    var requirements: Requirements { get }
    var platform: Platform { get }
}

extension ScenarioParameter {
    var platform: Platform { .all }
}

extension Scenario {

    /// Fans a single definition out into one scenario per value, mirroring pytest's
    /// `@pytest.mark.parametrize`. Each value supplies its own id suffix, name, and requirements,
    /// and the value is handed to the shared body.
    static func parameterized<Value: ScenarioParameter>(
        _ id: String,
        over values: [Value],
        run: @escaping @Sendable (Scenario.Context, Value) async throws -> Void
    ) -> [Scenario] {
        values.map { value in
            Scenario(
                "\(id).\(value.idSuffix)",
                value.displayName,
                requirements: value.requirements,
                platform: value.platform
            ) { context in
                try await run(context, value)
            }
        }
    }
}
