import Testing

@testable import FidoUI

@Suite("FidoUI Ceremony Lifecycle", .serialized)
@MainActor
struct CeremonyLifecycleTests {
    private func makeUI() -> FidoUI {
        FidoUI(testTransportFactory: { _ in
            fatalError("Lifecycle tests must not open a transport")
        })
    }

    @Test("An overlapping request fails without disturbing the active ceremony")
    func rejectsOverlappingRequest() async throws {
        let ui = makeUI()
        let started = AsyncStream<Void>.makeStream()
        let release = AsyncStream<Void>.makeStream()
        let first = Task {
            try await ui.performCeremony { () throws(FidoUI.Error) -> Int in
                started.continuation.yield(())
                for await _ in release.stream { break }
                return 1
            }
        }
        defer {
            release.continuation.finish()
            first.cancel()
        }
        for await _ in started.stream { break }

        do {
            _ = try await ui.performCeremony { () throws(FidoUI.Error) -> Int in
                Issue.record("An overlapping request must not start")
                return 2
            }
            Issue.record("Expected operationInProgress")
        } catch FidoUI.Error.operationInProgress {}

        release.continuation.finish()
        #expect(try await first.value == 1)
        #expect(try await ui.performCeremony { () throws(FidoUI.Error) in 3 } == 3)
    }

    @Test("Cancellation tears down the active ceremony before the next request", arguments: [false, true])
    func cancellationAllowsNextRequest(explicit: Bool) async throws {
        let ui = makeUI()
        let started = AsyncStream<Void>.makeStream()
        let release = AsyncStream<Void>.makeStream()
        var didFinish = false
        let task = Task {
            try await ui.performCeremony { () throws(FidoUI.Error) -> Int in
                started.continuation.yield(())
                for await _ in release.stream { break }
                didFinish = true
                return 1
            }
        }
        defer {
            release.continuation.finish()
            task.cancel()
        }
        for await _ in started.stream { break }

        if explicit {
            await ui.cancel()
            #expect(didFinish, "cancel() must wait for teardown")
        } else {
            task.cancel()
        }
        do {
            _ = try await task.value
            Issue.record("Expected cancellation")
        } catch FidoUI.Error.cancelled {}
        #expect(didFinish)
        #expect(try await ui.performCeremony { () throws(FidoUI.Error) in 2 } == 2)
    }

    @Test("A failed ceremony releases the instance for the next request")
    func failureAllowsNextRequest() async throws {
        let ui = makeUI()
        do {
            let _: Int = try await ui.performCeremony { () throws(FidoUI.Error) in
                throw .cancelled
            }
            Issue.record("Expected cancellation")
        } catch FidoUI.Error.cancelled {}
        #expect(try await ui.performCeremony { () throws(FidoUI.Error) in 2 } == 2)
    }
}
