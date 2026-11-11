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

@Suite("NFC connection lifecycle")
struct NFCConnectionLifecycleTests {
    private enum HostError: Error { case stopped }

    @Test("A successful response queued before invalidation is delivered once")
    func successBeforeInvalidation() throws {
        let queue = DispatchQueue(label: "nfc.test")
        let lifecycle = NFCConnectionLifecycle(queue: queue)
        let recorder = Recorder()
        let id = try register(lifecycle, queue: queue, recorder: recorder)
        queue.suspend()
        queue.async { lifecycle.complete(id, with: .success(Data([0x90, 0x00]))) }
        queue.async { lifecycle.invalidate(error: SmartCardConnectionError.cancelledByUser) }
        queue.resume()
        queue.sync {}
        #expect(recorder.results.count == 1)
        #expect(try #require(recorder.results.first).get() == Data([0x90, 0x00]))
    }

    @Test("Invalidation resumes a pending send once and ignores a late response")
    func invalidationBeforeResponse() throws {
        let queue = DispatchQueue(label: "nfc.test")
        let lifecycle = NFCConnectionLifecycle(queue: queue)
        let recorder = Recorder()
        let id = try register(lifecycle, queue: queue, recorder: recorder)
        queue.sync {
            lifecycle.invalidate(error: SmartCardConnectionError.cancelledByUser)
            lifecycle.complete(id, with: .success(Data([0x90, 0x00])))
            lifecycle.complete(id, with: .failure(HostError.stopped))
        }
        #expect(recorder.results.count == 1)
        expectCancellation(try #require(recorder.results.first))
    }

    @Test(
        "Invalidation drains all pending sends once and preserves the first close reason",
        arguments: [SmartCardConnectionError.cancelled, .cancelledByUser]
    )
    func repeatedInvalidation(_ reason: SmartCardConnectionError) throws {
        let queue = DispatchQueue(label: "nfc.test")
        let lifecycle = NFCConnectionLifecycle(queue: queue)
        let recorder = Recorder()
        _ = try register(lifecycle, queue: queue, recorder: recorder)
        _ = try register(lifecycle, queue: queue, recorder: recorder)
        queue.sync {
            lifecycle.invalidate(error: reason)
            lifecycle.invalidate(error: HostError.stopped)
            #expect(lifecycle.register { recorder.record($0) } == nil)
        }
        #expect(recorder.results.count == 3)
        for result in recorder.results { expectCancellation(result, expected: reason) }
    }

    @Test("Ordinary APDU errors complete once without closing the connection")
    func transmissionFailure() throws {
        let queue = DispatchQueue(label: "nfc.test")
        let lifecycle = NFCConnectionLifecycle(queue: queue)
        let recorder = Recorder()
        let id = try register(lifecycle, queue: queue, recorder: recorder)
        queue.sync {
            lifecycle.complete(id, with: .failure(HostError.stopped))
            lifecycle.complete(id, with: .success(Data()))
        }
        #expect(recorder.results.count == 1)
        guard case .failure(is HostError) = try #require(recorder.results.first) else {
            Issue.record("Expected the original transmission error")
            return
        }
        let next = try register(lifecycle, queue: queue, recorder: recorder)
        queue.sync { lifecycle.complete(next, with: .success(Data([1]))) }
        #expect(recorder.results.count == 2)
        #expect(try #require(recorder.results.last).get() == Data([1]))
    }

    @Test("An app close preserves its error for pending sends but not later sends")
    func appClose() throws {
        let queue = DispatchQueue(label: "nfc.test")
        let lifecycle = NFCConnectionLifecycle(queue: queue)
        let recorder = Recorder()
        _ = try register(lifecycle, queue: queue, recorder: recorder)
        queue.sync {
            lifecycle.invalidate(error: HostError.stopped)
            #expect(lifecycle.register { recorder.record($0) } == nil)
        }
        #expect(recorder.results.count == 2)
        guard case .failure(is HostError) = try #require(recorder.results.first) else {
            Issue.record("Expected the app's error for the in-flight send")
            return
        }
        expectConnectionLost(try #require(recorder.results.last))
    }

    @Test("A normal close fails pending and later sends with connectionLost")
    func normalClose() throws {
        let queue = DispatchQueue(label: "nfc.test")
        let lifecycle = NFCConnectionLifecycle(queue: queue)
        let recorder = Recorder()
        _ = try register(lifecycle, queue: queue, recorder: recorder)
        queue.sync {
            lifecycle.invalidate(error: nil)
            #expect(lifecycle.register { recorder.record($0) } == nil)
        }
        #expect(recorder.results.count == 2)
        for result in recorder.results { expectConnectionLost(result) }
    }

    @Test(
        "A closed connection cannot affect the next session",
        arguments: [SmartCardConnectionError.cancelled, .cancelledByUser]
    )
    func separateSessions(_ reason: SmartCardConnectionError) throws {
        let queue = DispatchQueue(label: "nfc.test")
        let old = NFCConnectionLifecycle(queue: queue)
        let next = NFCConnectionLifecycle(queue: queue)
        let oldRecorder = Recorder()
        let nextRecorder = Recorder()
        let oldID = try register(old, queue: queue, recorder: oldRecorder)
        let nextID = try register(next, queue: queue, recorder: nextRecorder)
        queue.sync {
            old.invalidate(error: reason)
            #expect(old !== next)
            #expect(old.register { oldRecorder.record($0) } == nil)
            old.complete(oldID, with: .success(Data()))
            next.complete(nextID, with: .success(Data([2])))
        }
        #expect(oldRecorder.results.count == 2)
        for result in oldRecorder.results { expectCancellation(result, expected: reason) }
        #expect(nextRecorder.results.count == 1)
        #expect(try #require(nextRecorder.results.first).get() == Data([2]))
    }

    @Test("User cancellation is distinguished from app invalidation", arguments: [false, true])
    func invalidationMapping(closing: Bool) {
        let error = NFCConnectionLifecycle.invalidationError(HostError.stopped, userCancelled: true, closing: closing)
        if closing {
            #expect(error == nil)
        } else {
            guard case SmartCardConnectionError.cancelledByUser? = error as? SmartCardConnectionError else {
                Issue.record("Expected user cancellation")
                return
            }
        }
        let other = NFCConnectionLifecycle.invalidationError(HostError.stopped, userCancelled: false, closing: closing)
        #expect(other is HostError)
    }

    private func register(_ lifecycle: NFCConnectionLifecycle, queue: DispatchQueue, recorder: Recorder) throws -> UUID
    {
        try queue.sync { try #require(lifecycle.register { recorder.record($0) }) }
    }

    private func expectCancellation(
        _ result: Result<Data, Error>,
        expected: SmartCardConnectionError = .cancelledByUser
    ) {
        guard case .failure(let error) = result else {
            Issue.record("Expected cancellation, got \(result)")
            return
        }
        switch (error as? SmartCardConnectionError, expected) {
        case (.cancelled?, .cancelled), (.cancelledByUser?, .cancelledByUser): break
        default: Issue.record("Expected \(expected), got \(error)")
        }
    }

    private func expectConnectionLost(_ result: Result<Data, Error>) {
        guard case .failure(let error) = result,
            case .connectionLost = error as? SmartCardConnectionError
        else {
            Issue.record("Expected connectionLost, got \(result)")
            return
        }
    }
}

private final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [Result<Data, Error>] = []

    var results: [Result<Data, Error>] { lock.withLock { stored } }

    func record(_ result: Result<Data, Error>) {
        lock.withLock { stored.append(result) }
    }
}
