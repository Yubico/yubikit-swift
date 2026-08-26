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

/// Records what each scenario actually did, because the test framework will not.
///
/// A skipped scenario is reported to swift-testing with `Test.cancel`, which emits no console event
/// at any verbosity — so `213 tests passed` reads identically whether every scenario ran or every
/// one bailed out. That is the failure mode this exists to prevent: a run that is green because it
/// tested nothing looks exactly like a run that is green because it tested everything.
///
/// Every skip is printed as it happens, and a summary is written when the process exits.
enum ScenarioOutcomeLog {

    private static let lock = NSLock()
    nonisolated(unsafe) private static var skips: [(id: String, reason: String)] = []
    nonisolated(unsafe) private static var ranCount = 0
    nonisolated(unsafe) private static var summaryScheduled = false

    /// Records a scenario that executed to completion.
    static func recordRan() {
        lock.withLock {
            ranCount += 1
            scheduleSummaryLocked()
        }
    }

    /// Records a scenario that was skipped, and prints it immediately.
    static func recordSkip(id: String, reason: String) {
        lock.withLock {
            skips.append((id, reason))
            scheduleSummaryLocked()
        }
        print("↷ SKIP  \(id)  —  \(reason)")
    }

    /// Must be called with `lock` held.
    private static func scheduleSummaryLocked() {
        guard !summaryScheduled else { return }
        summaryScheduled = true
        atexit(printSummary)
    }

    private static let printSummary: @convention(c) () -> Void = {
        let (ran, skipped) = lock.withLock { (ranCount, skips) }
        let total = ran + skipped.count
        guard total > 0 else { return }

        print("")
        print("──── scenario coverage: \(ran)/\(total) ran, \(skipped.count) skipped ────")
        guard !skipped.isEmpty else { return }
        // Group by reason: a single cause usually accounts for many skips, and the reasons are what
        // tell you whether the gap is expected.
        let byReason = Dictionary(grouping: skipped, by: \.reason).sorted { $0.value.count > $1.value.count }
        for (reason, entries) in byReason {
            print("  \(entries.count)×  \(reason)")
            for entry in entries.sorted(by: { $0.id < $1.id }) {
                print("        \(entry.id)")
            }
        }
        print("")
    }
}
