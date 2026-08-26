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
import Testing
import YubiKit

@testable import YubiKitIntegrationScenarios

#if canImport(YubiKitTwinTesting)
import YubiKitTwinTesting
#endif

// CLI knobs: YUBIKIT_ENABLE_TWINKIT=1, YUBIKEY_TEST_SERIALS,
// FORCE_SCP=automatic|scp11b|scp03, SCENARIO=<id-substring>.
enum ScenarioTests {

    static var usesTwinKit: Bool {
        #if canImport(YubiKitTwinTesting)
        true
        #else
        false
        #endif
    }

    static var backendConfigured: Bool {
        usesTwinKit || ProcessInfo.processInfo.environment["YUBIKEY_TEST_SERIALS"] != nil
    }

    static var configurationErrors: [String] {
        var errors: [String] = []
        if !usesTwinKit, case .failure(let error) = WiredConnectionProvider.serialConfiguration {
            errors.append(error.description)
        }
        if let filter = ProcessInfo.processInfo.environment["SCENARIO"] {
            if filter.isEmpty {
                errors.append("SCENARIO must not be empty")
            } else if !Scenario.Catalog.all.contains(where: {
                $0.id.localizedCaseInsensitiveContains(filter)
            }) {
                errors.append("SCENARIO '\(filter)' does not match any scenario id")
            }
        }
        if let value = ProcessInfo.processInfo.environment["FORCE_SCP"],
            !validSecureChannelValues.contains(value.lowercased())
        {
            errors.append("invalid FORCE_SCP value '\(value)' (expected automatic, scp11b, scp03, or none)")
        }
        #if canImport(YubiKitTwinTesting)
        if let error = TwinKitConnectionProvider.environmentConfigurationError {
            errors.append(error)
        }
        #endif
        return errors
    }

    static var configurationIsValid: Bool { configurationErrors.isEmpty }

    static func makeProvider() -> any ConnectionProvider {
        #if canImport(YubiKitTwinTesting)
        TwinKitConnectionProvider()
        #else
        WiredConnectionProvider()
        #endif
    }

    static var only: String? {
        ProcessInfo.processInfo.environment["SCENARIO"]
    }

    private static let validSecureChannelValues = ["", "none", "automatic", "auto", "scp11b", "11b", "scp03", "03"]

    static var forcedSecureChannel: SecureChannelPolicy {
        switch ProcessInfo.processInfo.environment["FORCE_SCP"]?.lowercased() {
        case "automatic", "auto": return .automatic
        case "scp11b", "11b": return .scp11b
        case "scp03", "03": return .scp03
        default: return .none
        }
    }

    static func run(_ scenario: Scenario) async throws {
        if let only, !scenario.id.localizedCaseInsensitiveContains(only) {
            try Test.cancel(Comment(rawValue: "scenario \(scenario.id) filtered out by SCENARIO='\(only)'"))
        }
        let result = await Scenario.Runner(provider: makeProvider(), secureChannel: forcedSecureChannel).run(scenario)
        switch result.status {
        case .passed:
            ScenarioOutcomeLog.recordRan()
        case .skipped(let reason):
            // `Test.cancel` alone is invisible in the console, so a skip is indistinguishable from
            // a pass. Log it before cancelling.
            ScenarioOutcomeLog.recordSkip(id: scenario.id, reason: reason)
            try Test.cancel(Comment(rawValue: "scenario \(scenario.id) skipped: \(reason)"))
        case .backendUnavailable(let reason):
            Issue.record(Comment(rawValue: "scenario \(scenario.id) backend unavailable: \(reason)"))
        case .failed, .errored, .running:
            var report = "scenario \(scenario.id) \(result.status)"
            for failure in result.failures {
                report += "\n  • \(failure.message)  (\(failure.location))"
            }
            if let thrown = result.thrownError {
                report += "\n  • threw: \(thrown)"
            }
            Issue.record(Comment(rawValue: report))
        }
    }

    /// The parameterized families declared by a suite: every catalog scenario in `suite` that is not
    /// one of the suite's enumerated cases. Driving `@Test(arguments:)` off this picks up a newly
    /// added family automatically — no per-case wrapper to forget and no fragile id matching.
    static func parameterizedFamilies(in suite: Scenario.Suite, besides enumeratedCases: [Scenario]) -> [Scenario] {
        let enumeratedIDs = Set(enumeratedCases.map(\.id))
        return Scenario.Catalog.scenarios(in: suite).filter { !enumeratedIDs.contains($0.id) }
    }

}

/// Parent suite for per-scenario tests; serialized because they share one attached key.
@Suite(
    "Scenarios",
    .serialized,
    .enabled(if: ScenarioTests.backendConfigured && ScenarioTests.configurationIsValid)
)
enum ScenarioSuites {}

@Test func scenarioConfigurationIsValid() {
    for error in ScenarioTests.configurationErrors {
        Issue.record(Comment(rawValue: error))
    }
}

@Test func hardwareSerialConfigurationIsStrict() throws {
    #expect(try WiredConnectionProvider.parseSerials("123 456,789").get() == [123, 456, 789])
    #expect(throws: SerialConfigurationError.invalidToken("abc")) {
        try WiredConnectionProvider.parseSerials("123,abc").get()
    }
    #expect(throws: SerialConfigurationError.invalidToken("")) {
        try WiredConnectionProvider.parseSerials("123,,456").get()
    }
}

@Test func teardownFailureFailsScenario() async {
    let scenario = Scenario("Connection.Teardown.failure", "teardown failure is reported") { context in
        await context.addTeardown { throw SyntheticTeardownError.failed }
    }
    let result = await Scenario.Runner(provider: UnusedProvider()).run(scenario)

    #expect(result.status == .failed)
    #expect(result.failures.count == 1)
    #expect(result.failures.first?.message.contains("teardown failed") == true)
}

@Test func scenarioIDsAreUnique() {
    let ids = Scenario.Catalog.allDeclared.map(\.id)
    let duplicates = Dictionary(grouping: ids, by: { $0 }).filter { $1.count > 1 }.keys.sorted()
    #expect(duplicates.isEmpty, "duplicate scenario ids: \(duplicates.joined(separator: ", "))")
}

// Each suite that declares parameterized families drives them from `parameterizedFamilies(in:besides:)`
// in a `@Test(arguments:)`. An empty result there would run zero cases while still reporting green, so
// guard that the families resolve — this fails loudly if a base id is renamed or a family stops being
// declared.
@Test func parameterizedFamiliesAreWired() {
    #expect(!ScenarioTests.parameterizedFamilies(in: .oath, besides: OATHScenario.allCases.map(\.scenario)).isEmpty)
    #expect(!ScenarioTests.parameterizedFamilies(in: .ctap2, besides: CTAP2Scenario.allCases.map(\.scenario)).isEmpty)
    #expect(!ScenarioTests.parameterizedFamilies(in: .piv, besides: PIVScenario.allCases.map(\.scenario)).isEmpty)
}

@Test(.enabled(if: ScenarioTests.backendConfigured && ScenarioTests.configurationIsValid))
func backendIsReachable() async throws {
    do {
        _ = try await ScenarioTests.makeProvider().deviceInfo()
    } catch let ProviderError.unavailable(reason) {
        Issue.record(
            Comment(
                rawValue:
                    "No YubiKey available for the selected scenario backend: \(reason)"
            )
        )
    }
}

private enum SyntheticTeardownError: Error {
    case failed
}

private struct UnusedProvider: ConnectionProvider {
    let capabilities = ProviderCapabilities(hasFIDO: false, supportsSecureChannel: false, isVirtual: true)
    let deviceTransport: DeviceTransport = .usb
    let ctap2Transport: CTAP2Transport = .ccid

    func makeSmartCardConnection() async throws -> any SmartCardConnection {
        throw ProviderError.unavailable("unused")
    }

    func makeFIDOConnection() async throws -> any FIDOConnection {
        throw ProviderError.unavailable("unused")
    }

    func deviceInfo() async throws -> DeviceInfo {
        throw ProviderError.unavailable("unused")
    }
}
