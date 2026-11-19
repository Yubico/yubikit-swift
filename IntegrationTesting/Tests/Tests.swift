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

@testable import YubiKit
@_spi(YubiInternal) @testable import YubiKitIntegrationScenarios

#if canImport(YubiKitTwinTesting)
@_spi(YubiInternal) import YubiKitTwinTesting
import YubiKitTwinSupport
#endif

// CLI knobs: YUBIKIT_ENABLE_TWINKIT=1, YUBIKEY_TEST_SERIALS,
// FORCE_SCP=automatic|scp11b|scp03, SCENARIO=<id-substring>.
enum ScenarioTests {

    /// Catalog entries for `suite`, narrowed by `SCENARIO` to the ids containing that substring.
    static func selected(in suite: Scenario.Suite) -> [Scenario] {
        let scenarios = Scenario.Catalog.scenarios(in: suite)
        guard let only else { return scenarios }
        return scenarios.filter { $0.id.localizedCaseInsensitiveContains(only) }
    }

    static func run(_ scenario: Scenario) async throws {
        let result = await Scenario.Runner(provider: makeProvider(), secureChannel: forcedSecureChannel).run(scenario) {
            switch $0 {
            case .touchPrompt(let scenario, let prompt), .reinsertPrompt(let scenario, let prompt):
                print("[\(scenario.id)] \(prompt)")
            default:
                break
            }
        }
        switch result.status {
        case .passed:
            await ScenarioOutcomeLog.shared.recordPassed()
        case .skipped(let reason):
            await ScenarioOutcomeLog.shared.recordSkip(id: scenario.id, reason: reason)
            try Test.cancel(Comment(rawValue: "scenario \(scenario.id) skipped: \(reason)"))
        case .backendUnavailable(let reason):
            await ScenarioOutcomeLog.shared.recordFailed(id: scenario.id, summary: "backend unavailable: \(reason)")
            Issue.record(Comment(rawValue: "scenario \(scenario.id) backend unavailable: \(reason)"))
        case .failed, .errored, .running:
            let summary = result.failures.first?.message ?? result.thrownError ?? "\(result.status)"
            await ScenarioOutcomeLog.shared.recordFailed(id: scenario.id, summary: summary)
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

    fileprivate static var backendConfigured: Bool {
        usesTwinKit || ProcessInfo.processInfo.environment["YUBIKEY_TEST_SERIALS"] != nil
    }

    fileprivate static var configurationErrors: [String] {
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

    fileprivate static var configurationIsValid: Bool { configurationErrors.isEmpty }

    fileprivate static func makeProvider() -> any ConnectionProvider {
        #if canImport(YubiKitTwinTesting)
        TwinKitConnectionProvider()
        #else
        WiredConnectionProvider()
        #endif
    }

    private static var usesTwinKit: Bool {
        #if canImport(YubiKitTwinTesting)
        true
        #else
        false
        #endif
    }

    private static var only: String? {
        ProcessInfo.processInfo.environment["SCENARIO"]
    }

    private static let validSecureChannelValues = ["", "none", "automatic", "auto", "scp11b", "11b", "scp03", "03"]

    private static var forcedSecureChannel: SecureChannelPolicy {
        switch ProcessInfo.processInfo.environment["FORCE_SCP"]?.lowercased() {
        case "automatic", "auto": return .automatic
        case "scp11b", "11b": return .scp11b
        case "scp03", "03": return .scp03
        default: return .none
        }
    }
}

/// Labels each parameterized case with the scenario it ran rather than an argument index.
extension Scenario: CustomTestStringConvertible {
    public var testDescription: String { "\(id) — \(name)" }
}

// Serialize device access because scenarios and probes use the same shared key.
@Suite(
    "Scenarios",
    .serialized,
    .reportsScenarioOutcomes,
    .enabled(if: ScenarioTests.backendConfigured && ScenarioTests.configurationIsValid)
)
enum ScenarioSuites {
    @Test static func backendIsReachable() async throws {
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
}

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

@Test(arguments: [ProviderError.unsupported("unsupported"), .unavailable("unavailable")])
func providerErrorPreservesFailures(error: ProviderError) async {
    let scenario = Scenario("Connection.Provider.failure", "provider error preserves failures") { context in
        context.record("assertion failed")
        context.log("body reached")
        await context.addTeardown { throw SyntheticTeardownError.failed }
        throw error
    }
    let result = await Scenario.Runner(provider: UnusedProvider()).run(scenario)

    #expect(result.status == .failed)
    #expect(result.failures.count == 2)
    #expect(result.failures.first?.message == "assertion failed")
    #expect(result.failures.last?.message.contains("teardown failed") == true)
    #expect(result.logs == ["body reached", "provider error: \(error)"])
}

@Test(arguments: [ProviderError.unsupported("unsupported"), .unavailable("unavailable")])
func providerErrorPreservesOutcome(error: ProviderError) async {
    let scenario = Scenario("Connection.Provider.outcome", "provider error preserves outcome") { context in
        context.log("body reached")
        await context.addTeardown { context.log("cleanup reached") }
        throw error
    }
    let result = await Scenario.Runner(provider: UnusedProvider()).run(scenario)

    switch error {
    case .unsupported(let reason): #expect(result.status == .skipped(reason: reason))
    case .unavailable(let reason): #expect(result.status == .backendUnavailable(reason: reason))
    }
    #expect(result.failures.isEmpty)
    #expect(result.logs == ["body reached", "provider error: \(error)", "cleanup reached"])
}

@Test(arguments: [false, true], [false, true])
func cancelledScenarioReportsOutcome(bodyFails: Bool, teardownFails: Bool) async {
    let scenario = Scenario("Connection.Cancellation.outcome", "cancelled scenario outcome") { context in
        if bodyFails { context.record("assertion failed") }
        await context.addTeardown {
            try Task.checkCancellation()
            context.log("cleanup reached")
            if teardownFails { throw SyntheticTeardownError.failed }
        }
        throw CancellationError()
    }
    let task = Task {
        withUnsafeCurrentTask { $0?.cancel() }
        return await Scenario.Runner(provider: UnusedProvider()).run(scenario)
    }
    let result = await task.value

    #expect(result.status == (bodyFails || teardownFails ? .failed : .skipped(reason: "cancelled")))
    #expect(result.failures.count == (bodyFails ? 1 : 0) + (teardownFails ? 1 : 0))
    if bodyFails { #expect(result.failures.first?.message == "assertion failed") }
    if teardownFails { #expect(result.failures.last?.message.contains("teardown failed") == true) }
    #expect(result.logs == ["scenario cancelled", "cleanup reached"])
}

@Test func scenarioIDsAreUnique() {
    let ids = Scenario.Catalog.allDeclared.map(\.id)
    let duplicates = Dictionary(grouping: ids, by: { $0 }).filter { $1.count > 1 }.keys.sorted()
    #expect(duplicates.isEmpty, "duplicate scenario ids: \(duplicates.joined(separator: ", "))")
}

// Check declarations independently of host filtering.
@Test func everySuiteDeclaresScenarios() {
    for suite in Scenario.Suite.allCases {
        #expect(Scenario.Catalog.allDeclared.contains { $0.suite == suite }, "suite \(suite) declares no scenarios")
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

#if canImport(YubiKitTwinTesting)
@Test func unavailableNFCKeepsSmartCardSession() async throws {
    let backend = TwinKitBackend(profile: .yubiKey5Nano)
    let connection = try await backend.openSmartCard(transport: .usb)
    let selected = try await connection.send(
        Data([
            0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17,
        ])
    )
    #expect(selected.suffix(2) == Data([0x90, 0x00]))
    let command = Data([0x00, 0x1d, 0x00, 0x00])
    let before = try await connection.send(command)
    #expect(before.suffix(2) == Data([0x90, 0x00]))
    do {
        _ = try await backend.openSmartCard(transport: .nfc)
        Issue.record("NFC connection succeeded on a USB-only profile")
    } catch TwinKitSupportError.unavailable {
    }
    #expect(try await connection.send(command) == before)
    connection.close(error: nil)
}
#endif

@Test(arguments: [
    ("5.7.4", DeviceTransport.usb, false, false),
    ("5.8.0", .usb, false, true),
    ("5.7.4", .usb, true, true),
    ("5.7.4", .nfc, false, true),
])
func ctap2CCIDFirmwareDependsOnSelectedRoute(
    version: String,
    transport: DeviceTransport,
    lightning: Bool,
    runs: Bool
) async {
    let scenario = Scenario(
        "Connection.CTAP2.route",
        "CTAP2 uses the selected smart-card route",
        requirements: Requirements(capabilities: [.fido2], requiresCTAP2OverCCID: true)
    ) { _ in }
    let applications = Capability.fido2.rawValue | (lightning ? 0 : Capability.oath.rawValue)
    let info = gateDevice(version: version, supported: [transport: applications], enabled: [transport: applications])
    let provider = GateProvider(deviceTransport: transport, info: info, usesLightning: lightning)
    let result = await Scenario.Runner(provider: provider).run(scenario)
    #expect(
        result.status
            == (runs ? .passed : .skipped(reason: "CTAP2 over USB CCID requires firmware ≥ 5.8.0 (device is 5.7.4)"))
    )
}

@Test(arguments: [
    (DeviceTransport.usb, "requires a smart-card (CCID) transport, unavailable on this backend"),
    (.nfc, "NFC reading is unavailable on this backend"),
])
func runnerSkipsUnavailableHostBeforeProbing(transport: DeviceTransport, reason: String) async {
    var provider = GateProvider(deviceTransport: transport)
    provider.capabilities.hasSmartCard = false
    let scenario = Scenario(
        "Connection.SmartCard.host",
        "Smart-card access depends on the host",
        requirements: Requirements(capabilities: [.oath])
    ) { _ in Issue.record("An unsupported host must not run the scenario") }

    let result = await Scenario.Runner(provider: provider).run(scenario)
    #expect(result.status == .skipped(reason: reason))
}

@Test(arguments: [
    (
        Capability.fido2.rawValue, Optional<UInt>.none,
        "requires the smart-card (CCID) interface on the selected YubiKey"
    ),
    (
        Capability.fido2.rawValue | Capability.oath.rawValue, Capability.fido2.rawValue,
        "the smart-card (CCID) interface is disabled on the selected YubiKey"
    ),
    (Capability.oath.rawValue, nil, nil),
])
func secureChannelRequiresAnAvailableUSBInterface(supported: UInt, enabled: UInt?, skipReason: String?) async {
    let info = gateDevice(supported: [.usb: supported], enabled: enabled.map { [.usb: $0] } ?? [:])
    let scenario = Scenario(
        "Connection.SCP.interface",
        "SCP needs a smart-card interface",
        requirements: Requirements(requiresSCP: true)
    ) { _ in }
    let result = await Scenario.Runner(provider: GateProvider(info: info)).run(scenario)
    #expect(result.status == (skipReason.map { .skipped(reason: $0) } ?? .passed))
}

@Test(arguments: [
    (UInt(0), UInt(0), false, "the selected YubiKey has no NFC interface"),
    (Capability.oath.rawValue, 0, false, "NFC applications are disabled on the selected YubiKey"),
    (
        Capability.oath.rawValue, Capability.oath.rawValue, true,
        "NFC is restricted on the selected YubiKey until USB reinsertion"
    ),
])
func nfcEligibilityUsesTheKeyConfiguration(supported: UInt, enabled: UInt, restricted: Bool, reason: String) {
    let info = gateDevice(supported: [.nfc: supported], enabled: [.nfc: enabled], nfcRestricted: restricted)
    #expect(
        Gate.evaluate(Requirements(), deviceInfo: info, transport: .nfc, provider: GateProvider().capabilities)
            == .skip(reason: reason)
    )
}

@Test func vettedSmartCardRouteStaysBoundToTheSelectedKey() async {
    let cache = DeviceInfoCache()
    #expect(await cache.acceptsAndCaches(gateDevice(), allowed: [1, 2], smartCardUsesLightning: false))
    #expect(await !cache.acceptsAndCaches(gateDevice(serial: 2), allowed: [1, 2], smartCardUsesLightning: true))
    #expect(await !cache.acceptsAndCaches(gateDevice(), allowed: [1, 2], smartCardUsesLightning: true))
    #expect(await cache.smartCardUsesLightning == false)
}

#if os(iOS)
@Test(.enabled(if: !NFCConnectionProvider.isAvailable))
func unavailableNFCReaderIsRejectedBeforeOpeningASession() async {
    do {
        _ = try await NFCConnectionProvider().makeSmartCardConnection()
        Issue.record("NFC opened without an available reader")
    } catch ProviderError.unsupported {
    } catch {
        Issue.record("unexpected error: \(error)")
    }
}
#endif

private func gateDevice(
    version: String = "5.7.4",
    serial: UInt = 1,
    supported: [DeviceTransport: UInt] = [:],
    enabled: [DeviceTransport: UInt] = [:],
    nfcRestricted: Bool = false
) -> DeviceInfo {
    DeviceInfo(
        version: Version(version)!,
        serialNumber: serial,
        supportedCapabilities: supported,
        config: DeviceConfig(enabledCapabilities: enabled, isNFCRestricted: nfcRestricted)
    )
}

private struct GateProvider: ConnectionProvider {
    var capabilities = ProviderCapabilities(hasFIDO: false, supportsSecureChannel: true, isVirtual: false)
    var deviceTransport: DeviceTransport = .usb
    var info: DeviceInfo?
    var usesLightning: Bool? = nil
    let ctap2Transport: CTAP2Transport = .ccid

    func selectedSmartCardUsesLightning() async -> Bool? { usesLightning }

    func deviceInfo() async throws -> DeviceInfo {
        guard let info else { throw ProviderError.unavailable("unexpected device-info probe") }
        return info
    }

    func makeSmartCardConnection() async throws -> any SmartCardConnection { throw ProviderError.unavailable("unused") }
    func makeFIDOConnection() async throws -> any FIDOConnection { throw ProviderError.unavailable("unused") }
}
