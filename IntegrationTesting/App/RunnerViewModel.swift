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
import SwiftUI
import YubiKit
@_spi(YubiInternal) import YubiKitIntegrationScenarios

@MainActor
final class RunnerViewModel: ObservableObject {

    enum Backend: String, CaseIterable, Identifiable {
        case wired = "Wired"
        case nfc = "NFC"
        var id: String { rawValue }
        var systemImage: String { self == .nfc ? "wave.3.right" : "cable.connector" }
    }

    // MARK: - State

    @Published var backend: Backend = .wired {
        didSet {
            guard oldValue != backend else { return }
            resetResults()
            refreshBackend()
        }
    }
    @Published var failuresOnly = false
    /// A failure is a bug (or a missed touch), so by default a run stops at the first one.
    @Published var stopOnFirstFailure = true
    @Published private(set) var stoppedAfterFailure: Scenario?
    @Published var secureChannel: SecureChannelPolicy = .none
    @Published private(set) var authorizedSerialNumber: UInt?

    @Published private(set) var results: [Scenario: Scenario.Result] = [:]
    @Published private(set) var runningScenario: Scenario?
    @Published private(set) var userPrompt: UserPrompt?

    /// Something the scenario needs the user to do with the key.
    struct UserPrompt: Equatable {
        let text: String
        let systemImage: String
    }
    @Published private(set) var isRunning = false
    @Published private(set) var ranCount = 0
    @Published private(set) var runTotal = 0
    @Published var backendAlert: BackendAlert?

    struct BackendAlert {
        let message: String
    }

    @Published private(set) var probedDevice: DeviceInfo?
    @Published private(set) var isProbing = false
    @Published private(set) var probeError: String?

    @Published private(set) var providerCaps: ProviderCapabilities?
    @Published private(set) var providerTransport: DeviceTransport?
    @Published private(set) var ctap2Transport: CTAP2Transport?

    private let suites = Scenario.Catalog.suites
    private var task: Task<Void, Never>?
    private var probeTask: Task<Void, Never>?

    init() {
        backend = availableBackends.first ?? .wired
        refreshBackend()
    }

    var availableBackends: [Backend] {
        #if os(iOS)
        return ScenarioConnection.hasNFCReader ? [.wired, .nfc] : [.wired]
        #else
        return [.wired]
        #endif
    }

    // MARK: - Test key authorization

    var canChangeAuthorization: Bool { !isRunning && !isProbing }

    static func isAuthorizationConfirmed(_ confirmation: String) -> Bool {
        confirmation == authorizationPhrase
    }

    /// Reads the YubiKey that would be authorized: the connected key for wired, a tapped key for NFC.
    func identifyTestKey() async throws -> DeviceInfo {
        guard canChangeAuthorization else {
            throw ProviderError.unavailable("Another operation is using the YubiKey.")
        }
        isProbing = true
        defer { isProbing = false }
        let device = try await ScenarioConnection.identifyYubiKey(over: backend == .nfc ? .nfc : .usb)
        try Task.checkCancellation()
        return device
    }

    func authorizeTestKey(_ device: DeviceInfo, confirmation: String) -> Bool {
        guard canChangeAuthorization, device.serialNumber > 0, Self.isAuthorizationConfirmed(confirmation) else {
            return false
        }
        authorizedSerialNumber = device.serialNumber
        resetResults()
        backendAlert = nil
        refreshBackend()
        return true
    }

    func revokeTestKeyAuthorization() {
        guard canChangeAuthorization else { return }
        authorizedSerialNumber = nil
        resetResults()
        backendAlert = nil
        refreshBackend()
    }

    private static let authorizationPhrase = "DANGEROUS"

    // MARK: - Gating

    func skipReason(_ scenario: Scenario) -> String? {
        guard let caps = providerCaps, let transport = providerTransport else { return "backend unavailable" }
        return scenario.skipReason(transport: transport, provider: caps, deviceInfo: probedDevice)
    }

    // MARK: - Filtering

    func visibleScenarios(in suite: Scenario.Suite) -> [Scenario] {
        Scenario.Catalog.scenarios(in: suite).filter(matches)
    }

    var visibleSuites: [Scenario.Suite] { suites.filter { !visibleScenarios(in: $0).isEmpty } }

    private func matches(_ scenario: Scenario) -> Bool {
        guard failuresOnly else { return true }
        let status = results[scenario]?.status
        return status?.isFailure == true
    }

    // MARK: - Counts

    func result(for scenario: Scenario) -> Scenario.Result? { results[scenario] }
    var passedCount: Int { results.values.filter { $0.status == .passed }.count }
    var failedCount: Int { results.values.filter { $0.status.isFailure }.count }
    var skippedCount: Int {
        results.values.filter { if case .skipped = $0.status { return true } else { return false } }.count
    }
    var totalCount: Int { Scenario.Catalog.all.count }

    func suiteCounts(_ suite: Scenario.Suite) -> (passed: Int, failed: Int, total: Int) {
        let all = Scenario.Catalog.scenarios(in: suite)
        let passed = all.filter { results[$0]?.status == .passed }.count
        let failed = all.filter { results[$0]?.status.isFailure == true }.count
        return (passed, failed, all.count)
    }

    // MARK: - Running

    func runAll() { run(Scenario.Catalog.all) }
    func runSuite(_ suite: Scenario.Suite) { run(Scenario.Catalog.scenarios(in: suite)) }
    func runOne(_ scenario: Scenario) { run([scenario]) }
    func runVisible() { run(visibleSuites.flatMap(visibleScenarios)) }
    func cancel() {
        task?.cancel()
        probeTask?.cancel()
    }

    private func run(_ scenarios: [Scenario]) {
        guard !isRunning, !isProbing, !scenarios.isEmpty else { return }
        guard let provider = makeProvider() else {
            for scenario in scenarios {
                results[scenario] = Scenario.Result(scenario: scenario, status: .skipped(reason: "backend unavailable"))
            }
            return
        }
        backendAlert = nil
        isRunning = true
        stoppedAfterFailure = nil
        ranCount = 0
        runTotal = scenarios.count
        let runner = Scenario.Runner(provider: provider, secureChannel: secureChannel)

        let (events, sink) = AsyncStream<Scenario.Event>.makeStream()
        let consumer = Task { @MainActor [weak self] in
            for await event in events { self?.apply(event) }
        }

        task = Task {
            for scenario in scenarios {
                if Task.isCancelled { break }
                self.results[scenario] = Scenario.Result(scenario: scenario, status: .running)
                let result = await runner.run(scenario) { event in sink.yield(event) }
                self.results[scenario] = result
                self.ranCount += 1
                if Task.isCancelled { break }
                if case .backendUnavailable(let reason) = result.status {
                    self.backendAlert = BackendAlert(message: reason)
                    break
                }
                if self.stopOnFirstFailure, result.status.isFailure {
                    self.stoppedAfterFailure = scenario
                    break
                }
            }
            sink.finish()
            await consumer.value
            self.isRunning = false
            self.runningScenario = nil
            self.userPrompt = nil
            self.task = nil
        }
    }

    func resetResults() {
        guard !isRunning else { return }
        results.removeAll()
        stoppedAfterFailure = nil
        ranCount = 0
        runTotal = 0
    }

    // MARK: - Device probe

    func probeDevice() {
        guard !isProbing, !isRunning, let provider = makeProvider() else { return }
        isProbing = true
        probedDevice = nil
        providerCaps = provider.capabilities
        probeError = nil
        probeTask = Task { [weak self] in
            guard let self else { return }
            defer {
                self.isProbing = false
                self.probeTask = nil
            }
            do {
                let device = try await provider.deviceInfo()
                var capabilities = provider.capabilities
                capabilities.hasLightning = await provider.selectedSmartCardUsesLightning() == true
                if capabilities.hasLightning {
                    capabilities.hasSmartCard = true
                    capabilities.supportsSecureChannel = true
                }
                try Task.checkCancellation()
                self.probedDevice = device
                self.providerCaps = capabilities
            } catch {
                if !Task.isCancelled { self.probeError = String(describing: error) }
            }
        }
    }

    // MARK: - Provider

    private func refreshBackend() {
        probedDevice = nil
        probeError = nil
        let provider = makeProvider()
        providerCaps = provider?.capabilities
        providerTransport = provider?.deviceTransport
        ctap2Transport = provider?.ctap2Transport
    }

    private func makeProvider() -> ScenarioConnection? {
        guard backend != .nfc || ScenarioConnection.hasNFCReader else { return nil }
        let allowed = authorizedSerialNumber.map { [$0] } ?? ScenarioConnection.allowedSerialNumbers
        return ScenarioConnection(transport: backend == .nfc ? .nfc : .usb, allowedSerialNumbers: allowed)
    }

    private func apply(_ event: Scenario.Event) {
        switch event {
        case .started(let scenario):
            runningScenario = scenario
        case .touchPrompt(_, let prompt):
            userPrompt = UserPrompt(text: prompt, systemImage: "hand.tap")
        case .reinsertPrompt(_, let prompt):
            userPrompt = UserPrompt(text: prompt, systemImage: "cable.connector")
        case .finished:
            runningScenario = nil
            userPrompt = nil
        }
    }
}

extension Scenario.Result.Status {
    fileprivate var isFailure: Bool {
        switch self {
        case .failed, .errored, .backendUnavailable: return true
        default: return false
        }
    }
}
