// Mock transport for wired and NFC UI scenarios. Session acquisition drives
// the real WebAuthn client against the mock backend without opening hardware.

import Foundation

@testable import FidoUI
@testable import YubiKit

actor MockTransportController: FidoUI.TransportControllerProtocol {

    private let webauthn: MockCTAP2Backend
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
    #if os(iOS)
    private var selectedWiredSession: FidoUI.ActiveSession?
    #endif

    init(
        webauthn: MockCTAP2Backend,
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
        #if os(iOS)
        if let session = selectedWiredSession {
            selectedWiredSession = nil
            return session
        }
        #endif
        return nil
    }

    func isWiredAvailable() -> Bool {
        transport == .wired
    }

    func awaitWired() async throws(FidoUI.Error) -> FidoUI.ActiveSession {
        if transport == .nfc {
            do {
                try await Task.sleep(for: .seconds(60))
            } catch {
                throw .cancelled
            }
            throw .cancelled
        }
        if ProcessInfo.processInfo.arguments.contains("--slow-wired"), acquireCount == 0 {
            do {
                try await Task.sleep(for: .seconds(4))
            } catch {
                throw .cancelled
            }
        }
        let session = try await provideSession()
        #if os(iOS)
        if acquireCount == 1 { selectedWiredSession = session }
        #endif
        return session
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
    webauthn: MockCTAP2Backend,
    pinSetup: MockPINSetupBackend = MockPINSetupBackend(),
    minPINLength: Int = 4,
    transport: FidoUI.Presenter.CeremonyTransport = defaultMockTransport,
    pinSetupLatency: Duration = .milliseconds(700)
) -> FidoUI {
    FidoUI(
        presentationAnchor: Runner.presentationAnchor,
        isPinPrioritized: ProcessInfo.processInfo.arguments.contains("--pin-prioritized"),
        testTransportFactory: { _ in
            MockTransportController(
                webauthn: webauthn,
                pinSetup: pinSetup,
                minPINLength: minPINLength,
                transport: transport,
                pinSetupLatency: pinSetupLatency
            )
        }
    )
}

/// Mock transport mode selected by the host app's launch arguments.
/// `--mock-nfc` → NFC; anything else → wired.
var defaultMockTransport: FidoUI.Presenter.CeremonyTransport {
    ProcessInfo.processInfo.arguments.contains("--mock-nfc") ? .nfc : .wired
}
