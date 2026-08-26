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
import YubiKit

struct RequireFailure: Error {}

struct SkipScenario: Error { let reason: String }

private final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storedFailures: [Scenario.Failure] = []
    private var storedLogs: [String] = []

    var failures: [Scenario.Failure] {
        lock.lock()
        defer { lock.unlock() }
        return storedFailures
    }
    var logs: [String] {
        lock.lock()
        defer { lock.unlock() }
        return storedLogs
    }
    func add(_ failure: Scenario.Failure) {
        lock.lock()
        defer { lock.unlock() }
        storedFailures.append(failure)
    }
    func addLog(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        storedLogs.append(message)
    }
}

extension Scenario {

    /// Per-run fixture handed to a scenario body.
    actor Context {

        private struct Teardown: Sendable {
            let work: @Sendable () async throws -> Void
            let location: SourceLocation
        }

        nonisolated private let scenario: Scenario
        nonisolated let provider: ConnectionProvider
        nonisolated private let secureChannel: SecureChannelPolicy
        nonisolated private let onEvent: @Sendable (Scenario.Event) -> Void
        nonisolated private let recorder = Recorder()

        nonisolated var recordedFailures: [Scenario.Failure] { recorder.failures }
        nonisolated var recordedLogs: [String] { recorder.logs }

        private var teardown: [Teardown] = []
        // Memoized as in-flight tasks so concurrent callers share one connection.
        private var smartCardConnectionTask: Task<any SmartCardConnection, Error>?
        private var fidoConnectionTask: Task<any FIDOConnection, Error>?
        private var scpKeyParamsTask: Task<SCPKeyParams?, Error>?

        init(
            scenario: Scenario,
            provider: ConnectionProvider,
            secureChannel: SecureChannelPolicy = .none,
            onEvent: @escaping @Sendable (Scenario.Event) -> Void
        ) {
            self.scenario = scenario
            self.provider = provider
            self.secureChannel = secureChannel
            self.onEvent = onEvent
        }

        // MARK: - Assertions (synchronous)

        @discardableResult
        nonisolated func expect(
            _ condition: Bool,
            _ message: @autoclosure () -> String = "",
            file: String = #fileID,
            line: Int = #line
        ) -> Bool {
            if !condition {
                let text = message()
                fail(text.isEmpty ? "expectation failed" : text, file: file, line: line)
            }
            return condition
        }

        @discardableResult
        nonisolated func expectEqual<T: Equatable>(
            _ lhs: T,
            _ rhs: T,
            _ message: @autoclosure () -> String = "",
            file: String = #fileID,
            line: Int = #line
        ) -> Bool {
            let prefix = message()
            return expect(
                lhs == rhs,
                "\(prefix.isEmpty ? "" : prefix + ": ")expected \(lhs) == \(rhs)",
                file: file,
                line: line
            )
        }

        nonisolated func require(
            _ condition: Bool,
            _ message: @autoclosure () -> String = "",
            file: String = #fileID,
            line: Int = #line
        ) throws {
            if !condition {
                let text = message()
                fail(text.isEmpty ? "requirement failed" : text, file: file, line: line)
                throw RequireFailure()
            }
        }

        nonisolated func require<T>(
            _ value: T?,
            _ message: @autoclosure () -> String = "",
            file: String = #fileID,
            line: Int = #line
        ) throws -> T {
            guard let value else {
                let text = message()
                fail(text.isEmpty ? "required a non-nil value" : text, file: file, line: line)
                throw RequireFailure()
            }
            return value
        }

        nonisolated func record(_ message: String, file: String = #fileID, line: Int = #line) {
            fail(message, file: file, line: line)
        }

        /// Abort the body and report the scenario as skipped.
        nonisolated func skip(_ reason: String) throws -> Never {
            log("⏭ \(reason) — skipping")
            throw SkipScenario(reason: reason)
        }

        // MARK: - Output

        nonisolated func log(_ message: String) {
            recorder.addLog(message)
        }

        nonisolated func touch(_ prompt: String) {
            onEvent(.touchPrompt(scenario, prompt))
        }

        // MARK: - Connections (internal, memoized per scenario)

        func smartCardConnection() async throws -> any SmartCardConnection {
            if let smartCardConnectionTask { return try await smartCardConnectionTask.value }
            let task = Task { try await provider.makeSmartCardConnection() }
            smartCardConnectionTask = task
            return try await task.value
        }

        func fidoConnection() async throws -> any FIDOConnection {
            if let fidoConnectionTask { return try await fidoConnectionTask.value }
            let task = Task { try await provider.makeFIDOConnection() }
            fidoConnectionTask = task
            return try await task.value
        }

        func reconnectWhenOverNFC() async {
            guard provider.deviceTransport == .nfc else { return }

            let task = smartCardConnectionTask
            smartCardConnectionTask = nil
            scpKeyParamsTask = nil

            if let connection = try? await task?.value {
                await connection.close(error: nil)
            }
        }

        // MARK: - Secure channel (internal, memoized per scenario)

        func scpKeyParams() async throws -> SCPKeyParams? {
            if let scpKeyParamsTask { return try await scpKeyParamsTask.value }
            let task = Task { try await resolveScpKeyParams() }
            scpKeyParamsTask = task
            return try await task.value
        }

        // MARK: - Lifecycle (internal)

        func addTeardown(
            file: String = #fileID,
            line: Int = #line,
            _ work: @escaping @Sendable () async throws -> Void
        ) {
            teardown.append(Teardown(work: work, location: SourceLocation(fileID: file, line: line)))
        }

        func runTeardown() async {
            for item in teardown.reversed() {
                do {
                    try await item.work()
                } catch {
                    record("teardown failed: \(error)", file: item.location.fileID, line: item.location.line)
                }
            }
            teardown.removeAll()
            if let connection = try? await smartCardConnectionTask?.value { await connection.close(error: nil) }
            if let connection = try? await fidoConnectionTask?.value { await connection.close(error: nil) }
            smartCardConnectionTask = nil
            fidoConnectionTask = nil
            scpKeyParamsTask = nil
        }
    }
}

// MARK: - Private helpers

extension Scenario.Context {

    private nonisolated func fail(_ message: String, file: String, line: Int) {
        recorder.add(Scenario.Failure(message: message, location: .init(fileID: file, line: line)))
    }

    private func resolveScpKeyParams() async throws -> SCPKeyParams? {
        guard secureChannel != .none else { return nil }
        guard provider.capabilities.supportsSecureChannel else {
            throw ProviderError.unsupported("\(secureChannel) requires Secure Channel (SCP) support")
        }
        switch secureChannel {
        case .none: return nil
        case .scp03: return try scp03DefaultKeyParams()
        case .scp11b: return try await scp11bKeyParams()
        case .automatic:
            if try await provider.deviceInfo().version >= Version("5.7.2")! {
                return try await scp11bKeyParams()
            }
            return try scp03DefaultKeyParams()
        }
    }

    private func scp03DefaultKeyParams() throws -> SCPKeyParams {
        try SCP03KeyParams(keyRef: SCPKeyRef(kid: .scp03, kvn: 0xff), staticKeys: StaticKeys.defaultKeys())
    }

    private func scp11bKeyParams() async throws -> SCPKeyParams {
        let connection = try await smartCardConnection()
        let keyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)
        do {
            let securityDomain = try await SecurityDomainSession.makeSession(connection: connection)
            let chain = try await securityDomain.getCertificateBundle(for: keyRef)
            guard let leaf = chain.last, case let .ec(publicKey) = leaf.publicKey else {
                throw ProviderError.unsupported("SCP11b leaf certificate unavailable on this device")
            }
            return try SCP11KeyParams(keyRef: keyRef, pkSdEcka: publicKey)
        } catch let error as ProviderError {
            throw error
        } catch {
            throw ProviderError.unsupported("SCP11b unavailable on this device: \(error)")
        }
    }
}
