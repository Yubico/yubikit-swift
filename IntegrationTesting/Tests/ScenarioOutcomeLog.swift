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

/// Per-scenario tally: swift-testing counts test functions, not scenarios, and `Test.cancel` prints
/// nothing, so a skipped scenario is otherwise indistinguishable from a passing one.
actor ScenarioOutcomeLog {

    static let shared = ScenarioOutcomeLog()

    private var passed = 0
    private var failures: [(id: String, summary: String)] = []
    private var skips: [(id: String, reason: String)] = []

    func recordPassed() {
        passed += 1
    }

    func recordFailed(id: String, summary: String) {
        failures.append((id, summary))
        print("✘ FAIL  \(id)  —  \(summary)")
    }

    func recordSkip(id: String, reason: String) {
        skips.append((id, reason))
        print("↷ SKIP  \(id)  —  \(reason)")
    }

    /// Called once, after every scenario in the suite has finished.
    func report() {
        let total = passed + failures.count + skips.count
        guard total > 0 else { return }

        print("")
        print("──── \(total) scenarios: \(passed) passed, \(failures.count) failed, \(skips.count) skipped ────")

        if !failures.isEmpty {
            print("")
            print("  FAILED")
            for failure in failures.sorted(by: { $0.id < $1.id }) {
                print("    ✘  \(failure.id)  —  \(failure.summary)")
            }
        }

        if !skips.isEmpty {
            print("")
            print("  SKIPPED")
            let byReason = Dictionary(grouping: skips, by: \.reason)
                .sorted { $0.value.count == $1.value.count ? $0.key < $1.key : $0.value.count > $1.value.count }
            for (reason, entries) in byReason {
                print("    \(entries.count)×  \(reason)")
                for entry in entries.sorted(by: { $0.id < $1.id }) {
                    print("          \(entry.id)")
                }
            }
        }
        print("")
    }
}

/// swift-testing has no after-all-tests hook; a non-recursive suite trait scopes the suite itself,
/// which wraps every test it contains.
struct ScenarioOutcomeReport: SuiteTrait, TestScoping {

    func scopeProvider(for test: Test, testCase: Test.Case?) -> Self? {
        test.isSuite ? self : nil
    }

    func provideScope(
        for test: Test,
        testCase: Test.Case?,
        performing function: @Sendable () async throws -> Void
    ) async throws {
        try await function()
        await ScenarioOutcomeLog.shared.report()
    }
}

extension SuiteTrait where Self == ScenarioOutcomeReport {
    static var reportsScenarioOutcomes: Self { .init() }
}
