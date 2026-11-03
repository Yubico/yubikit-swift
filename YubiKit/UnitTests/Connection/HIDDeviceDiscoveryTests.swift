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

#if os(macOS)
import Foundation
import Testing

@testable import YubiKit

@Suite(.timeLimit(.minutes(1)))
struct HIDDeviceDiscoveryTests {
    @Test("discovery waits until a device appears")
    func waitsForDevice() async throws {
        let discovery = DelayedDiscovery()
        let device = try await waitForDevice(cancellationError: FIDOConnectionError.cancelled) {
            () async throws(FIDOConnectionError) in
            await discovery.devices()
        }
        #expect(device == 42)
    }

    @Test("a waiting HID discovery stops on cancellation")
    func cancelWhileWaiting() async throws {
        let polled = Promise<Void>()
        let task = Task {
            try await waitForDevice(cancellationError: FIDOConnectionError.cancelled) {
                () async throws(FIDOConnectionError) -> [Int] in
                await polled.fulfill(())
                return []
            }
        }
        defer { task.cancel() }
        try await polled.value()
        task.cancel()
        do {
            _ = try await task.value
            Issue.record("Cancelled HID discovery succeeded")
        } catch FIDOConnectionError.cancelled {
        }
    }

    @Test("FIDO acquisition rejects an already cancelled task", arguments: [false, true])
    func cancelledFIDO(factory: Bool) async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await factory ? HIDFIDOConnection.makeConnection() : HIDFIDOConnection()
        }
        do {
            _ = try await task.value
            Issue.record("Cancelled FIDO acquisition succeeded")
        } catch FIDOConnectionError.cancelled {
        } catch {
            Issue.record("Unexpected cancellation error: \(error)")
        }
    }

    @Test("OTP acquisition rejects an already cancelled task", arguments: [false, true])
    func cancelledOTP(factory: Bool) async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await factory ? HIDOTPConnection.makeConnection() : HIDOTPConnection()
        }
        do {
            _ = try await task.value
            Issue.record("Cancelled OTP acquisition succeeded")
        } catch OTPConnectionError.cancelled {
        } catch {
            Issue.record("Unexpected cancellation error: \(error)")
        }
    }
}

private actor DelayedDiscovery {
    private var firstPoll = true

    func devices() -> [Int] {
        if firstPoll {
            firstPoll = false
            return []
        }
        return [42]
    }
}
#endif
