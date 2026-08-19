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
import YubiKitIntegrationScenarios

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
            results.removeAll()
            refreshBackend()
        }
    }
    @Published var failuresOnly = false
    @Published var secureChannel: SecureChannelPolicy = .none

    @Published private(set) var results: [Scenario: Scenario.Result] = [:]
    @Published private(set) var runningScenario: Scenario?
    @Published private(set) var touchPrompt: String?
    @Published private(set) var isRunning = false
    @Published private(set) var ranCount = 0
    @Published private(set) var runTotal = 0
    @Published var backendAlert: BackendAlert?

    struct BackendAlert: Identifiable {
        let id = UUID()
        let message: String
    }

    @Published private(set) var probedDevice: DeviceInfo?
    @Published private(set) var isProbing = false
    @Published private(set) var probeError: String?

    @Published private(set) var providerCaps: ProviderCapabilities?
    @Published private(set) var providerTransport: DeviceTransport?
    @Published private(set) var ctap2Transport: CTAP2Transport?

    let suites = Scenario.Catalog.suites
    private var task: Task<Void, Never>?

    init() {
        backend = availableBackends.first ?? .wired
        refreshBackend()
    }

    var availableBackends: [Backend] {
        #if os(iOS)
        return [.wired, .nfc]
        #else
        return [.wired]
        #endif
    }

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
        return status == .failed || status == .errored
    }

    // MARK: - Counts

    func result(for scenario: Scenario) -> Scenario.Result? { results[scenario] }
    var passedCount: Int { results.values.filter { $0.status == .passed }.count }
    var failedCount: Int { results.values.filter { $0.status == .failed || $0.status == .errored }.count }
    var skippedCount: Int {
        results.values.filter { if case .skipped = $0.status { return true } else { return false } }.count
    }
    var totalCount: Int { Scenario.Catalog.all.count }

    func suiteCounts(_ suite: Scenario.Suite) -> (passed: Int, failed: Int, total: Int) {
        let all = Scenario.Catalog.scenarios(in: suite)
        let passed = all.filter { results[$0]?.status == .passed }.count
        let failed = all.filter { results[$0]?.status == .failed || results[$0]?.status == .errored }.count
        return (passed, failed, all.count)
    }

    // MARK: - Running

    func runAll() { run(Scenario.Catalog.all) }
    func runSuite(_ suite: Scenario.Suite) { run(Scenario.Catalog.scenarios(in: suite)) }
    func runOne(_ scenario: Scenario) { run([scenario]) }
    func runVisible() { run(visibleSuites.flatMap(visibleScenarios)) }
    func cancel() { task?.cancel() }

    private func run(_ scenarios: [Scenario]) {
        guard !isRunning, !isProbing else { return }
        guard let provider = makeProvider() else {
            for scenario in scenarios {
                results[scenario] = Scenario.Result(scenario: scenario, status: .skipped(reason: "backend unavailable"))
            }
            return
        }
        isRunning = true
        ranCount = 0
        runTotal = scenarios.count
        let runner = Scenario.Runner(provider: provider, secureChannel: secureChannel)

        var streamContinuation: AsyncStream<Scenario.Event>.Continuation!
        let events = AsyncStream<Scenario.Event> { streamContinuation = $0 }
        let sink = streamContinuation!
        let consumer = Task { @MainActor [weak self] in
            for await event in events { self?.apply(event) }
        }

        task = Task { [weak self] in
            guard let self else { return }
            await self.resolveRuntimeCapabilities(provider, for: self.backend)
            for scenario in scenarios {
                if Task.isCancelled { break }
                if let reason = self.skipReason(scenario) {
                    self.results[scenario] = Scenario.Result(scenario: scenario, status: .skipped(reason: reason))
                    self.ranCount += 1
                    continue
                }
                self.results[scenario] = Scenario.Result(scenario: scenario, status: .running)
                let result = await runner.run(scenario) { event in sink.yield(event) }
                self.results[scenario] = result
                self.ranCount += 1
                if case .backendUnavailable(let reason) = result.status {
                    self.backendAlert = BackendAlert(message: reason)
                    break
                }
            }
            sink.finish()
            await consumer.value
            self.isRunning = false
            self.runningScenario = nil
            self.touchPrompt = nil
        }
    }

    func resetResults() {
        guard !isRunning else { return }
        results.removeAll()
    }

    // MARK: - Device probe

    func probeDevice() {
        guard !isProbing, !isRunning, let provider = makeProvider() else { return }
        isProbing = true
        probeError = nil
        Task { [weak self] in
            guard let self else { return }
            do {
                self.probedDevice = try await provider.deviceInfo()
            } catch {
                self.probeError = String(describing: error)
            }
            self.isProbing = false
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
        if let provider {
            let backend = backend
            Task { [weak self] in await self?.resolveRuntimeCapabilities(provider, for: backend) }
        }
    }

    private func resolveRuntimeCapabilities(_ provider: any ConnectionProvider, for backend: Backend) async {
        let hasLightning = await provider.lightningKeyConnected()
        guard self.backend == backend else { return }
        providerCaps?.hasLightning = hasLightning
    }

    private func makeProvider() -> (any ConnectionProvider)? {
        switch backend {
        case .wired:
            return WiredConnectionProvider()
        case .nfc:
            #if os(iOS)
            return NFCConnectionProvider()
            #else
            return nil
            #endif
        }
    }

    private func apply(_ event: Scenario.Event) {
        switch event {
        case .started(let scenario):
            runningScenario = scenario
        case .touchPrompt(_, let prompt): touchPrompt = prompt
        case .finished:
            runningScenario = nil
            touchPrompt = nil
        }
    }
}
