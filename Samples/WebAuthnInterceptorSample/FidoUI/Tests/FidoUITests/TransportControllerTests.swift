import Foundation
import Testing
@_spi(YubiInternal) import YubiKit

@testable import FidoUI

@Suite("FidoUI.TransportController Tests", .serialized)
struct TransportControllerTests {

    @Test("Cancel closes a connection returned after wired discovery stops")
    func cancelDuringConnectionDiscovery() async throws {
        let gate = Gate<any Connection>()
        let connection = ProbeConnection()
        let driver = FidoUI.WiredTransportDriver(
            connect: { await gate.wait() },
            makeSession: { _ in
                Issue.record("Session setup must not run after cancellation")
                return try makeActiveSession()
            },
            devicePresent: { true }
        )
        let transport = try makeTransport(driver: driver)

        await transport.start()
        await gate.waitUntilEntered()
        #expect(await transport.isWiredAvailable())
        await transport.cancel()
        #expect(!(await transport.isWiredAvailable()))
        await gate.release(connection)
        #expect(await connection.waitForClose(timeout: .seconds(1)))

        let state = await connection.state
        #expect(state.closeCount == 1)
        #expect(state.waitCount == 0)
        #expect(await transport.wired() == nil)
    }

    @Test("Cancel closes an in-flight connection and never publishes its late session")
    func cancelDuringSessionSetup() async throws {
        let gate = Gate<FidoUI.ActiveSession>()
        let connection = ProbeConnection()
        let activeSession = try makeActiveSession()
        let driver = FidoUI.WiredTransportDriver(
            connect: { connection },
            makeSession: { _ in await gate.wait() },
            devicePresent: { false }
        )
        let transport = try makeTransport(driver: driver)

        await transport.start()
        await gate.waitUntilEntered()
        #expect(await transport.isWiredAvailable())
        await transport.cancel()
        await gate.release(activeSession)
        #expect(
            !(await connection.waitForWaitStarted(timeout: .milliseconds(250))),
            "A stopped transport must not wait on a session returned after cancellation"
        )

        let state = await connection.state
        #expect(state.closeCount == 1)
        #expect(state.waitCount == 0)
        #expect(await transport.wired() == nil)
        do {
            _ = try await transport.awaitWired()
            Issue.record("A stopped transport must not return a session")
        } catch FidoUI.Error.cancelled {}
    }

    private func makeTransport(driver: FidoUI.WiredTransportDriver) throws -> FidoUI.TransportController {
        FidoUI.TransportController(
            origin: try WebAuthn.Origin("https://example.com"),
            isPublicSuffix: { _ in false },
            wiredDriver: driver
        )
    }

    private func makeActiveSession() throws -> FidoUI.ActiveSession {
        let origin = try WebAuthn.Origin("https://example.com")
        let client = WebAuthn.Client(
            authenticator: UnusedAuthenticator(),
            origin: origin,
            isPublicSuffix: { _ in false }
        )
        return FidoUI.ActiveSession(
            client: client,
            minPINLength: 4,
            hasPin: false,
            setPIN: { _ in },
            changePIN: { _, _ in }
        )
    }
}

private actor Gate<Value: Sendable> {
    private var enteredContinuation: CheckedContinuation<Void, Never>?
    private var valueContinuation: CheckedContinuation<Value, Never>?
    private var hasEntered = false

    func wait() async -> Value {
        hasEntered = true
        enteredContinuation?.resume()
        enteredContinuation = nil
        return await withCheckedContinuation { valueContinuation = $0 }
    }

    func waitUntilEntered() async {
        guard !hasEntered else { return }
        await withCheckedContinuation { enteredContinuation = $0 }
    }

    func release(_ value: Value) {
        valueContinuation?.resume(returning: value)
        valueContinuation = nil
    }
}

private actor ProbeConnection: Connection {
    struct State: Sendable {
        let closeCount: Int
        let waitCount: Int
    }

    private var closeCount = 0
    private var waitCount = 0
    private var isClosed = false
    private var closeContinuation: CheckedContinuation<Void, Never>?
    private let closeEvents: AsyncStream<Void>
    private let closeEventContinuation: AsyncStream<Void>.Continuation
    private let waitEvents: AsyncStream<Void>
    private let waitEventContinuation: AsyncStream<Void>.Continuation

    init() {
        let close = AsyncStream<Void>.makeStream()
        closeEvents = close.stream
        closeEventContinuation = close.continuation
        let wait = AsyncStream<Void>.makeStream()
        waitEvents = wait.stream
        waitEventContinuation = wait.continuation
    }

    var state: State { State(closeCount: closeCount, waitCount: waitCount) }

    func waitForClose(timeout: Duration) async -> Bool {
        if isClosed { return true }
        return await Self.waitForEvent(closeEvents, timeout: timeout)
    }

    func waitForWaitStarted(timeout: Duration) async -> Bool {
        if waitCount > 0 { return true }
        return await Self.waitForEvent(waitEvents, timeout: timeout)
    }

    func close(error: (any Error)?) async {
        closeCount += 1
        isClosed = true
        closeEventContinuation.yield(())
        closeContinuation?.resume()
        closeContinuation = nil
    }

    func waitUntilClosed() async -> (any Error)? {
        waitCount += 1
        waitEventContinuation.yield(())
        if !isClosed {
            await withCheckedContinuation { closeContinuation = $0 }
        }
        return nil
    }

    private static func waitForEvent(
        _ events: AsyncStream<Void>,
        timeout: Duration
    ) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                for await _ in events { return true }
                return false
            }
            group.addTask {
                do {
                    try await Task.sleep(for: timeout)
                } catch {
                    return false
                }
                return false
            }
            let observed = await group.next() ?? false
            group.cancelAll()
            return observed
        }
    }
}

private struct UnusedAuthenticator: WebAuthn.AuthenticatorBackend {
    func makeCredential(
        options: WebAuthn.Registration.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization,
        enterpriseRpIds: Set<String>,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>
    ) async -> WebAuthn.StatusStream<WebAuthn.Registration.Response> {
        WebAuthn.StatusStream { _ in }
    }

    func getAssertions(
        options: WebAuthn.Authentication.Options,
        clientData: WebAuthn.ClientData,
        authorization: WebAuthn.Authorization,
        allowedExtensions: Set<WebAuthn.Extension.Identifier>
    ) async -> WebAuthn.StatusStream<[WebAuthn.Authentication.Response]> {
        WebAuthn.StatusStream { _ in }
    }
}
