import Testing

@testable import FidoUI
@testable import YubiKit

/// Covers `FidoUI.serialized(_:)` — concurrent calls run sequentially so
/// they don't race for `activeTransport`, the alert window, or the panel
/// model.
@Suite("FidoUI Ceremony Queue", .serialized)
@MainActor
struct CeremonyQueueTests {

    private func makeUI() -> FidoUI {
        FidoUI(testTransportFactory: { _ in
            fatalError("transport factory should not run in serialized tests")
        })
    }

    @Test("Concurrent calls execute bodies in submission order, never overlapping")
    func serializedQueuesCallsInSubmissionOrder() async throws {
        let ui = makeUI()

        let order = Box<[String]>([])
        let firstStarted = Box(false)
        let release = AsyncStream<Void>.makeStream()

        let firstTask = Task<Int, Error> { @MainActor in
            try await ui.serialized { () throws(FidoUI.Error) -> Int in
                order.value.append("first.start")
                firstStarted.value = true
                for await _ in release.stream { break }
                order.value.append("first.end")
                return 1
            }
        }

        // Wait until the first body has started and parked on the stream.
        for _ in 0..<200 {
            if firstStarted.value { break }
            await Task.yield()
        }
        #expect(firstStarted.value, "First body must run immediately")

        let secondTask = Task<Int, Error> { @MainActor in
            try await ui.serialized { () throws(FidoUI.Error) -> Int in
                order.value.append("second.start")
                return 2
            }
        }

        // Yield generously — second body must not run while first is parked.
        for _ in 0..<200 { await Task.yield() }
        #expect(
            order.value == ["first.start"],
            "Second body must not start while first is still running, saw: \(order.value)"
        )

        // Release the first body; both should now complete in order.
        release.continuation.yield()
        release.continuation.finish()

        let firstResult = try await firstTask.value
        let secondResult = try await secondTask.value
        #expect(firstResult == 1)
        #expect(secondResult == 2)
        #expect(order.value == ["first.start", "first.end", "second.start"])
    }

    /// `serialized` is a typed-throws funnel: a body that throws must surface
    /// the same error to its caller. The implementation routes outcomes
    /// through `Result<R, FidoUI.Error>` to work around the typed-throws +
    /// `Task.failure` mismatch — this test pins that round-trip.
    @Test("Body throws propagate through serialized to the caller")
    func serializedPropagatesThrownError() async throws {
        let ui = makeUI()

        do {
            let _: Int = try await ui.serialized { () throws(FidoUI.Error) in
                throw .cancelled
            }
            Issue.record("Should have thrown .cancelled")
        } catch FidoUI.Error.cancelled {}
    }

    /// The chain tail is a `Task<Void, Never>` fence so a thrown body still
    /// completes the fence — the next caller chains off `.finished`, not off a
    /// cancelled/failed Task that would never resolve. Without the fence, a
    /// single throw would deadlock every subsequent call on this instance.
    @Test("Next caller runs after a prior body throws (chain tail does not deadlock)")
    func serializedRunsNextCallerAfterPriorThrow() async throws {
        let ui = makeUI()

        let firstTask = Task<Int, Error> { @MainActor in
            try await ui.serialized { () throws(FidoUI.Error) -> Int in
                throw .cancelled
            }
        }

        do {
            _ = try await firstTask.value
            Issue.record("First should have thrown")
        } catch FidoUI.Error.cancelled {}

        // Second call must complete normally — the prior throw must not
        // jam the chain.
        let result = try await ui.serialized { () throws(FidoUI.Error) -> Int in 42 }
        #expect(result == 42)
    }
}
