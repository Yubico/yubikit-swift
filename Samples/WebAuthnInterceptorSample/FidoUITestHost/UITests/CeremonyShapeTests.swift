import XCTest

final class CeremonyShapeTests: FidoUITestBase {

    /// UP-only authenticator (no PIN, no UV): straight to touch and out.
    func testNoPINNoUV() {
        tapScenario("auth_no_pin")
        expectSuccess()
    }

    /// Stream emits `.processing` then `.waitingForUser` mid-flow before
    /// `.finished`. Exercises the in-app `.processing` and `.touch` panels
    /// which the other scenarios skip by emitting `.finished` immediately.
    func testTouchRequiredPanelAppears() {
        tapScenario("flow_touch_required")
        // The touch panel pulses with `.repeatForever` while visible, which
        // keeps the app from going idle — `waitForExistence` blocks on app
        // idle and times out even though `.exists` is true. Poll directly.
        pollForExistence(app.staticTexts["touch_prompt_title"], timeout: TestTimeouts.normal)
        expectSuccess()
    }

    /// Full "signed up, now sign in" journey: register a new passkey, the
    /// success panel auto-dismisses after 2s, then auth begins and the
    /// picker appears for the multi-credential rpId. User taps the
    /// just-registered credential.
    func testRegisterThenAuthenticate() {
        tapScenario("flow_register_then_auth")
        // Registration auto-dismisses after 2s via success panel's .task
        // before auth starts. Poll directly: `waitForExistence` waits for
        // app-idle before each poll, which the running auto-dismiss task
        // can defeat — same workaround as `testTouchRequiredPanelAppears`.
        pollForExistence(app.staticTexts["success_title"], timeout: 12)
        // Picker arrives after `getAssertion` + 4× `getNextAssertion`. Only
        // the first one pays the 2.5s `waitingForUser` cost; the
        // getNextAssertion mocks pass `touchDelay: .zero` (real CTAP
        // doesn't gate those on touch). ~3-5s total.
        pollForExistence(app.staticTexts["credential_picker_title"], timeout: 12)
        let firstRow = app.buttons["credential_row_0"]
        assertElementExists(firstRow, timeout: TestTimeouts.fast)
        firstRow.tap()
        expectSuccess()
    }

    /// First makeCredential stream errors with `connectionError` →
    /// `authenticatorNotAvailable`. `runCeremony` switches to `.reconnect`
    /// phase and shows the unified waiting panel before retrying.
    func testReconnectBridgeAfterDrop() {
        tapScenario("flow_connection_drop_mid_ceremony")
        assertElementExists(app.staticTexts["waiting_for_key_title"], timeout: TestTimeouts.slow)
        expectSuccess()
    }
}
