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

    /// Runs scenarios against a backend.
    public struct Runner: Sendable {

        private let provider: ConnectionProvider
        private let secureChannel: SecureChannelPolicy

        public init(
            provider: ConnectionProvider,
            secureChannel: SecureChannelPolicy = .none
        ) {
            self.provider = provider
            self.secureChannel = secureChannel
        }

        public func run(
            _ scenario: Scenario,
            onEvent: @escaping @Sendable (Scenario.Event) -> Void = { _ in }
        ) async -> Scenario.Result {
            onEvent(.started(scenario))

            if !scenario.platform.runsHere {
                return finish(
                    .init(scenario: scenario, status: .skipped(reason: "\(scenario.platform) only")),
                    onEvent
                )
            }

            do {
                let info = scenario.requirements.needsDeviceInfo ? try await provider.deviceInfo() : nil
                var capabilities = provider.capabilities
                if scenario.requirements.requiresLightning {
                    capabilities.hasLightning = await provider.lightningKeyConnected()
                }
                if case .skip(let reason) = Gate.evaluate(
                    scenario.requirements,
                    deviceInfo: info,
                    transport: provider.deviceTransport,
                    provider: capabilities
                ) {
                    return finish(.init(scenario: scenario, status: .skipped(reason: reason)), onEvent)
                }
            } catch {
                return finish(.init(scenario: scenario, status: backendStatus(for: error)), onEvent)
            }

            let context = Scenario.Context(
                scenario: scenario,
                provider: provider,
                secureChannel: secureChannel,
                onEvent: onEvent
            )
            let clock = ContinuousClock()
            let start = clock.now
            var thrownError: String?
            var bodyStatus: Scenario.Result.Status?
            do {
                try await scenario.run(context)
            } catch is RequireFailure {
            } catch let skip as SkipScenario {
                bodyStatus = .skipped(reason: skip.reason)
            } catch is CancellationError where Task.isCancelled {
                bodyStatus = .skipped(reason: "cancelled")
                context.log("scenario cancelled")
            } catch let error as ProviderError {
                bodyStatus = backendStatus(for: error)
                context.log("provider error: \(error)")
            } catch {
                thrownError = String(describing: error)
            }
            let duration = clock.now - start
            // Cleanup must still send commands after the scenario task is cancelled.
            await Task { await context.runTeardown() }.value

            let failures = context.recordedFailures
            let logs = context.recordedLogs
            let status: Scenario.Result.Status
            if thrownError != nil {
                status = .errored
            } else if !failures.isEmpty {
                status = .failed
            } else if let bodyStatus {
                status = bodyStatus
            } else {
                status = .passed
            }

            return finish(
                .init(
                    scenario: scenario,
                    status: status,
                    failures: failures,
                    thrownError: thrownError,
                    duration: duration,
                    logs: logs
                ),
                onEvent
            )
        }

        // MARK: - Private helpers

        private func backendStatus(for error: Error) -> Scenario.Result.Status {
            switch error {
            case ProviderError.unsupported(let reason): return .skipped(reason: reason)
            case ProviderError.unavailable(let reason): return .backendUnavailable(reason: reason)
            default: return .backendUnavailable(reason: String(describing: error))
            }
        }

        private func finish(
            _ result: Scenario.Result,
            _ onEvent: @escaping @Sendable (Scenario.Event) -> Void
        ) -> Scenario.Result {
            onEvent(.finished(result))
            return result
        }
    }
}
