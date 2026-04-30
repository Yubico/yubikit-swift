import XCTest

// End-to-end UI tests driving the real FidoUI + FidoUI presenter stack against
// MockWebAuthnBackend / MockPINSetupBackend scenarios. No hardware.
//
// Scenarios divide into two groups:
// - Flows: multi-step user journeys spanning 3+ panels.
// - Short dead-enders: one-shot paths that terminate on cancel or critical
//   error and can't naturally live inside a longer flow.
//
// Runs on both macOS and iOS. The mock transport's default mode is `.wired`
// (see `defaultMockTransport`) so iOS's picker commits immediately to wired
// and exercises the same inline-PIN flow as macOS HID. NFC-prefetch flow is
// covered separately by `E2EFlowTests_iOS`, which opts into `.nfc` via a
// launch argument.
final class E2EFlowTests: FidoUITestBase {

    func testFlowFirstTimeSetup() {
        tapScenario("flow_first_time_setup")
        assertElementExists(app.staticTexts["create_pin_title"])
        submitNewPIN("123456")
        assertElementExists(app.staticTexts["pin_created_title"])
        app.buttons["pin_created_continue_button"].tap()
        // Cached PIN pre-fills the field on retry — tap Continue without typing.
        assertElementExists(app.secureTextFields["pin_input_field"])
        app.buttons["continue_button"].tap()
        expectSuccess()
    }

    func testFlowForcePinChange() {
        tapScenario("flow_force_pin_change")
        // The SDK throws `.forcePinChange` before the PIN prompt; FidoUI's
        // catch arm dispatches the changePIN flow — no initial PIN entry,
        // straight to the change-PIN form.
        assertElementExists(app.staticTexts["change_pin_title"])
        typePIN("oldPIN", into: "current_pin_input")
        typePIN("newPIN", into: "new_pin_input")
        typePIN("newPIN", into: "repeat_pin_input")
        app.buttons["change_pin_button"].tap()
        assertElementExists(app.staticTexts["pin_changed_title"])
        app.buttons["pin_changed_continue_button"].tap()
        // Post-recovery PIN field is pre-filled with the cached new PIN;
        // submitPIN clears first so we end up with exactly "newPIN".
        submitPIN("newPIN")
        expectSuccess()
    }

    func testFlowForcePinChangeComplexityThenSuccess() {
        tapScenario("flow_force_pin_change_complexity")
        assertElementExists(app.staticTexts["change_pin_title"])
        assertElementExists(app.secureTextFields["current_pin_input"], timeout: TestTimeouts.fast)
        typePIN("oldPIN", into: "current_pin_input")
        typePIN("weak", into: "new_pin_input")
        typePIN("weak", into: "repeat_pin_input")
        let changeButton = app.buttons["change_pin_button"]
        changeButton.tap()

        // After the complexity reject the panel re-arms with the validation
        // message visible. Wait for that text to appear — it's a direct
        // re-arm signal that doesn't race button-state animations.
        assertElementExists(
            app.staticTexts["change_pin_validation_message"],
            timeout: TestTimeouts.slow
        )

        // Form clears all fields on retry; user re-enters all three.
        typePIN("oldPIN", into: "current_pin_input")
        typePIN("strongPIN", into: "new_pin_input")
        typePIN("strongPIN", into: "repeat_pin_input")
        changeButton.tap()

        assertElementExists(app.staticTexts["pin_changed_title"])
        app.buttons["pin_changed_continue_button"].tap()
        submitPIN("strongPIN")
        expectSuccess()
    }

    /// Wrong current PIN during force-PIN-change → form re-arms with the
    /// "current PIN is incorrect" message. Asserts the message text directly:
    /// it's the only signal that `SetupRecovery.classifySetupError`'s
    /// `pinInvalid` branch is wired correctly vs falling through to the
    /// generic "Failed. Please try again." default. Then re-types the
    /// correct PIN and runs through to success to exercise the full
    /// recovery path.
    func testFlowForcePinChangeWrongCurrent() {
        tapScenario("flow_force_pin_change_wrong_current")
        assertElementExists(app.staticTexts["change_pin_title"])
        typePIN("wrongPIN", into: "current_pin_input")
        typePIN("newPIN", into: "new_pin_input")
        typePIN("newPIN", into: "repeat_pin_input")
        app.buttons["change_pin_button"].tap()

        let exp = expectation(
            for: predicateForSwiftUIText("current PIN is incorrect"),
            evaluatedWith: app.staticTexts["change_pin_validation_message"]
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [exp], timeout: TestTimeouts.slow),
            .completed,
            "change-PIN form should re-arm with the 'current PIN incorrect' message after pinInvalid"
        )

        // Form clears all fields on retry; re-enter all three with the
        // correct current PIN.
        typePIN("correctPIN", into: "current_pin_input")
        typePIN("newPIN", into: "new_pin_input")
        typePIN("newPIN", into: "repeat_pin_input")
        app.buttons["change_pin_button"].tap()

        assertElementExists(app.staticTexts["pin_changed_title"])
        app.buttons["pin_changed_continue_button"].tap()
        submitPIN("newPIN")
        expectSuccess()
    }

    func testFlowProgressivePINRetries() {
        tapScenario("flow_progressive_pin_retries")
        submitPIN("wrong1")
        assertPINRetriesRemaining(7)
        submitPIN("wrong2")
        assertPINRetriesRemaining(6)
        // 3rd consecutive miss trips the CTAP 2.1 soft block — the form does
        // not re-arm; the pinAuthBlocked panel takes over (no Retry button).
        submitPIN("wrong3")
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["flow_progressive_pin_retries"], timeout: TestTimeouts.fast)
    }

    /// One wrong PIN, form re-arms with retry counter, correct PIN succeeds.
    /// Counterpart to `flow_uv_retry_then_success` for the PIN re-arm path —
    /// the soft-block test above doesn't cover successful recovery. macOS-only
    /// via the class-level gate; the iOS equivalent
    /// (`E2EFlowTests_iOS.testFlowPINRetryThenSuccess`) exercises the
    /// `.pinRejected` re-prompt path through `runCeremony`'s catch.
    func testFlowPINRetryThenSuccess() {
        tapScenario("flow_pin_retry_then_success")
        submitPIN("wrong")
        assertPINRetriesRemaining(7)
        submitPIN("123456")
        expectSuccess()
    }

    func testFlowUVRetryThenSuccess() {
        tapScenario("flow_uv_retry_then_success")
        assertFingerprintRetriesRemaining(2)
        app.buttons["retry_uv_button"].tap()
        assertFingerprintRetriesRemaining(1)
        app.buttons["retry_uv_button"].tap()
        expectSuccess()
    }

    func testFlowUVExhaustionPINFallback() {
        tapScenario("flow_uv_exhaustion_pin_fallback")
        assertFingerprintRetriesRemaining(2)
        app.buttons["retry_uv_button"].tap()
        assertFingerprintRetriesRemaining(1)
        app.buttons["retry_uv_button"].tap()
        // After exhaustion the SDK throws `.uvBlocked` and FidoUI renders
        // the locked panel with PIN+Cancel — gives the user an explicit
        // "sensor locked" moment before they enter PIN.
        assertElementExists(app.staticTexts["fingerprint_locked_title"], timeout: TestTimeouts.slow)
        app.buttons["use_pin_button"].tap()
        submitPIN("123456")
        expectSuccess()
    }

    func testFlowUVDeclineToPIN() {
        tapScenario("flow_uv_decline_to_pin")
        assertElementExists(app.staticTexts["fingerprint_retry_title"])
        app.buttons["use_pin_button"].tap()
        submitPIN("123456")
        expectSuccess()
    }

    func testFlowTouchRequired() {
        tapScenario("flow_touch_required")
        // The touch panel pulses with `.repeatForever` while visible, which
        // keeps the app from going idle — `waitForExistence` blocks on app
        // idle and times out even though `.exists` is true. Poll directly.
        pollForExistence(app.staticTexts["touch_prompt_title"], timeout: TestTimeouts.normal)
        expectSuccess()
    }

    func testFlowRegisterThenAuth() {
        tapScenario("flow_register_then_auth")
        // Registration auto-dismisses after 2s via success panel's .task
        // before auth starts. Poll directly: `waitForExistence` waits for
        // app-idle before each poll, which the running auto-dismiss task
        // can defeat — same workaround as `testFlowTouchRequired`.
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

    func testAuthNoPIN() {
        tapScenario("auth_no_pin")
        expectSuccess()
    }

    func testAuthCancelAtPIN() {
        tapScenario("auth_cancel_at_pin")
        assertElementExists(app.secureTextFields["pin_input_field"], timeout: TestTimeouts.fast)
        app.buttons["cancel_button"].tap()
        assertElementExists(app.buttons["auth_cancel_at_pin"], timeout: TestTimeouts.fast)
    }

    func testAuthNoCredentials() {
        tapScenario("auth_no_credentials")
        assertElementExists(app.staticTexts["error_title"])
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["auth_no_credentials"], timeout: TestTimeouts.fast)
    }

    func testErrPINAuthBlocked() {
        tapScenario("err_pin_auth_blocked")
        submitPIN("123456")
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["err_pin_auth_blocked"], timeout: TestTimeouts.fast)
    }

    func testErrUVBlocked() {
        tapScenario("err_uv_blocked")
        // UV-only key with no PIN fallback: each miss decrements retries, the
        // last tap surfaces .uvBlocked as a critical error.
        assertFingerprintRetriesRemaining(2)
        app.buttons["retry_uv_button"].tap()
        assertFingerprintRetriesRemaining(1)
        app.buttons["retry_uv_button"].tap()
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["err_uv_blocked"], timeout: TestTimeouts.fast)
    }

    /// First makeCredential stream errors with `connectionError` →
    /// `authenticatorNotAvailable`. runCeremony switches to `.reconnect`
    /// phase and shows the unified waiting panel. The bridge panel must
    /// appear before success.
    func testFlowConnectionDropMidCeremony() {
        tapScenario("flow_connection_drop_mid_ceremony")
        assertElementExists(app.staticTexts["waiting_for_key_title"], timeout: TestTimeouts.slow)
        expectSuccess()
    }

    /// Two matching credentials → picker → user taps Cancel. Cancel returns
    /// the user to the catalog (treated as `.completed`).
    func testAuthCancelAtPicker() {
        tapScenario("auth_cancel_at_picker")
        assertElementExists(app.staticTexts["credential_picker_title"], timeout: TestTimeouts.slow)
        app.buttons["credential_picker_cancel_button"].tap()
        assertElementExists(app.buttons["auth_cancel_at_picker"], timeout: TestTimeouts.fast)
    }

    /// applySetup's session acquire throws transient on the first attempt
    /// after the user submits a new PIN. The createPIN form re-arms with the
    /// failure message; resubmitting the same PIN succeeds.
    func testFlowSetupTransientConnectFail() {
        tapScenario("flow_setup_transient_connect_fail")
        assertElementExists(app.staticTexts["create_pin_title"])
        submitNewPIN("123456")
        // The transient retry message comes from `runPINSetupLoop`'s
        // `currentError` and lands in `create_pin_validation_message`'s
        // `value` (SwiftUI `Text` content goes to AXValue on macOS, not
        // AXLabel — same reason `predicateForSwiftUIText` matches both).
        let exp = expectation(
            for: predicateForSwiftUIText("Failed to connect"),
            evaluatedWith: app.staticTexts["create_pin_validation_message"]
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [exp], timeout: TestTimeouts.slow),
            .completed,
            "createPIN form should re-arm with retry message after transient connect fail"
        )
        submitNewPIN("123456")
        assertElementExists(app.staticTexts["pin_created_title"], timeout: TestTimeouts.slow)
        app.buttons["pin_created_continue_button"].tap()
        // Post-recovery ceremony re-arms the PIN entry with the cached PIN
        // pre-filled — tap Continue to consume it (mirrors `testFlowFirstTimeSetup`).
        assertElementExists(app.secureTextFields["pin_input_field"])
        app.buttons["continue_button"].tap()
        expectSuccess()
    }

    /// Regression: a permanent host-side failure during PIN setup recovery
    /// must surface as a terminal error panel, not loop the createPIN form.
    func testErrSetupPermanentFailure() {
        tapScenario("err_setup_permanent_failure")
        assertElementExists(app.staticTexts["create_pin_title"])
        submitNewPIN("123456")
        // setPIN throws → applySetup classifies as .fatal → inline error panel
        // with OK only (no Retry).
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["err_setup_permanent_failure"], timeout: TestTimeouts.fast)
    }
}
