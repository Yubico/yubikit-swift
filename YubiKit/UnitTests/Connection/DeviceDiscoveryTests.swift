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

@Suite(.timeLimit(.minutes(1)))
struct DeviceDiscoveryTests {
    private enum DiscoveryError: Error, Equatable {
        case cancelled
        case failed
    }

    @Test("cancellation before discovery does not poll")
    func alreadyCancelled() async throws {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await waitForDevice(cancellationError: DiscoveryError.cancelled) {
                () async throws(DiscoveryError) -> [Int] in
                Issue.record("Cancelled discovery must not poll")
                return [1]
            }
        }
        do {
            _ = try await task.value
            Issue.record("Cancelled discovery succeeded")
        } catch {
            #expect(error as? DiscoveryError == .cancelled)
        }
    }

    @Test("cancellation stops waiting when no device is available")
    func cancelWhileWaiting() async throws {
        let polled = Promise<Void>()
        let task = Task {
            try await waitForDevice(cancellationError: DiscoveryError.cancelled) {
                () async throws(DiscoveryError) -> [Int] in
                await polled.fulfill(())
                return []
            }
        }
        defer { task.cancel() }
        try await polled.value()
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Cancelled discovery succeeded")
        } catch {
            #expect(error as? DiscoveryError == .cancelled)
        }
    }

    @Test("USB connection initialization rejects an already cancelled task")
    func cancelledUSBConnection() async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await USBSmartCardConnection()
        }
        do {
            _ = try await task.value
            Issue.record("Cancelled USB connection succeeded")
        } catch SmartCardConnectionError.cancelled {
        } catch {
            Issue.record("Unexpected cancellation error: \(error)")
        }
    }

    @Test("discovery failures are propagated")
    func discoveryFailure() async {
        do {
            let _: Int = try await waitForDevice(cancellationError: DiscoveryError.cancelled) {
                () async throws(DiscoveryError) in
                throw .failed
            }
            Issue.record("Discovery failure was ignored")
        } catch {
            #expect(error == .failed)
        }
    }
}
