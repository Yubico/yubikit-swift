// Mock transport for FidoUI E2E scenarios. Substitutes a canned
// `ActiveSession` whose `WebAuthn.Client` is built via
// `WebAuthn.Client.mocked(backend:)` so scenarios drive the real retry /
// setup-recovery / error flows without opening any transport.
//
// `transport` controls which path the iOS picker takes:
//   - `.wired` (default): `isWiredAvailable()` returns true so iOS
//     commits to wired and runs the same inline-PIN flow as macOS HID.
//     Body iterations build sessions through `awaitWired`.
//   - `.nfc`: `isWiredAvailable()` returns false so iOS times out the
//     picker and chooses NFC. Body iterations build sessions through
//     `openNFC`. Used by `E2EFlowTests_iOS` to exercise the NFC
//     prefetch UI flow.
// macOS ignores `transport` because its picker is always `.wired`.

import Foundation

@testable import FidoUI
@testable import YubiKit

actor MockTransportController: FidoUI.TransportControllerProtocol {

    private let webauthn: MockWebAuthnBackend
    private let pinSetup: MockPINSetupBackend
    private let minPINLength: Int
    private let transport: FidoUI.Presenter.CeremonyTransport
    /// Latency injected before each `setPIN` / `changePIN` call so the
    /// processing panel is observable in UI tests. Default 700 ms
    /// matches a typical YubiKey response time; pass `.zero` from tests
    /// that don't care about the panel.
    private let pinSetupLatency: Duration

    /// Fires per session-acquire (both `awaitWired` and `openNFC`),
    /// incrementing the count argument. Scenarios use this to fail
    /// specific attempts (e.g. `count == 2 → throw` to exercise transient
    /// connect failures during setup recovery). Closure is untyped so
    /// scenarios can raise either a `FidoUI.Error` directly or an
    /// arbitrary error that the actor maps to
    /// `.authenticatorNotAvailable`.
    nonisolated(unsafe) var onAcquire: ((Int) async throws -> Void)?
    private var acquireCount = 0

    init(
        webauthn: MockWebAuthnBackend,
        pinSetup: MockPINSetupBackend = MockPINSetupBackend(),
        minPINLength: Int = 4,
        transport: FidoUI.Presenter.CeremonyTransport = .wired,
        pinSetupLatency: Duration = .milliseconds(700)
    ) {
        self.webauthn = webauthn
        self.pinSetup = pinSetup
        self.minPINLength = minPINLength
        self.transport = transport
        self.pinSetupLatency = pinSetupLatency
    }

    func start() {
        // No-op: tests have no real wired loop.
    }

    func wired() -> FidoUI.ActiveSession? {
        // Always nil so `waitForWiredWithPanel` falls through to
        // `awaitWired`, which routes through `provideSession` for
        // count + onAcquire bookkeeping. The picker uses
        // `isWiredAvailable` instead, which doesn't build a session.
        nil
    }

    func isWiredAvailable() -> Bool {
        transport == .wired
    }

    func awaitWired() async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        // Simulate the production loop's reconnect latency between body
        // iterations — without this, the mock returns the next session
        // instantly and the waiting-for-key panel that
        // `waitForWiredWithPanel` shows on reconnect never renders to
        // the screen, breaking tests like
        // `testFlowConnectionDropMidCeremony` that assert on it.
        if acquireCount > 0 {
            try? await Task.sleep(for: .milliseconds(500))
        }
        return try await provideSession()
    }

    #if os(iOS)
    func openNFC(alertMessage: String) async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        try await provideSession()
    }

    func closeNFC(successMessage: String?) async {
        // No-op in tests.
    }
    #endif

    func stopWiredLoop() async {
        // No-op: tests have no real wired loop.
    }

    func cancel() async {}

    /// Builds the canned `ActiveSession` after running the per-attempt
    /// hook. Both transport paths funnel through here so scenarios get
    /// platform-agnostic counter semantics.
    private func provideSession() async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        acquireCount += 1
        if let hook = onAcquire {
            do {
                try await hook(acquireCount)
            } catch let err as FidoUI.Error {
                throw err
            } catch {
                throw .webAuthn(.authenticatorNotAvailable(source: .here()))
            }
        }
        let client: WebAuthn.Client
        do {
            client = try WebAuthn.Client.mocked(backend: webauthn)
        } catch {
            throw .webAuthn(.internalError("Mock client init failed: \(error)", source: .here()))
        }
        // Reflect the scenario's `onGetInfo` so `ActiveSession.hasPin` matches
        // what the SDK would observe — drives the `.uvBlocked` recovery
        // panel's PIN-vs-fatal branch.
        let hasPin: Bool
        do throws(CTAP2.SessionError) {
            hasPin = try await webauthn.getInfo().options.clientPin == true
        } catch {
            hasPin = false
        }
        let pinSetup = self.pinSetup
        let latency = self.pinSetupLatency
        return FidoUI.ActiveSession(
            client: client,
            minPINLength: minPINLength,
            hasPin: hasPin,
            setPIN: { pin in
                try? await Task.sleep(for: latency)
                try await pinSetup.onSetPIN(pin)
            },
            changePIN: { current, new in
                try? await Task.sleep(for: latency)
                try await pinSetup.onChangePIN(current, new)
            }
        )
    }
}

/// Builds a FidoUI wired to a `MockTransportController`. The
/// `testTransportFactory` init is internal, accessed via
/// `@testable import FidoUI`.
///
/// `transport` defaults to whatever `defaultMockTransport` reads from
/// the host app's launch arguments — `--mock-nfc` selects NFC, anything
/// else stays wired. UI tests inject the launch arg via the
/// `extraLaunchArguments` override on `FidoUITestBase` so an entire
/// test class commits to one transport mode.
@MainActor
func makeMockedFidoUI(
    webauthn: MockWebAuthnBackend,
    pinSetup: MockPINSetupBackend = MockPINSetupBackend(),
    minPINLength: Int = 4,
    transport: FidoUI.Presenter.CeremonyTransport = defaultMockTransport,
    pinSetupLatency: Duration = .milliseconds(700)
) -> FidoUI {
    FidoUI(testTransportFactory: { _ in
        MockTransportController(
            webauthn: webauthn,
            pinSetup: pinSetup,
            minPINLength: minPINLength,
            transport: transport,
            pinSetupLatency: pinSetupLatency
        )
    })
}

/// Mock transport mode selected by the host app's launch arguments.
/// `--mock-nfc` → NFC; anything else → wired.
var defaultMockTransport: FidoUI.Presenter.CeremonyTransport {
    ProcessInfo.processInfo.arguments.contains("--mock-nfc") ? .nfc : .wired
}
