// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

#if os(macOS)

import Foundation
import Testing

@testable import YubiKit

@Suite("HID packet queue cancellation tests")
struct HIDPacketQueueCancellationTests {

    @Test("a second receive cannot replace a cancelled pending receive")
    func cancelledReceiveLeavesQueueAvailable() async throws {
        let queue = HIDPacketQueue()
        let pendingReceive = try queue.receive().get()

        if case .failure(.busy) = queue.receive() {
        } else {
            Issue.record("Expected a concurrent receive to fail with busy")
        }

        #expect(queue.withdraw(pendingReceive) === pendingReceive)
        await pendingReceive.cancel(with: FIDOConnectionError.cancelled)
        do {
            _ = try await pendingReceive.value()
            Issue.record("Expected the withdrawn receive to be cancelled")
        } catch let error as FIDOConnectionError {
            if case .cancelled = error {
            } else {
                Issue.record("Unexpected receive error: \(error)")
            }
        }

        let nextReceive = try queue.receive().get()
        let frame = Data([0x01, 0x02, 0x03])
        let waitingReceive = queue.enqueue(frame)
        #expect(waitingReceive === nextReceive)
        await waitingReceive?.fulfill(frame)

        #expect(try await nextReceive.value() == frame)
    }
}

#endif
