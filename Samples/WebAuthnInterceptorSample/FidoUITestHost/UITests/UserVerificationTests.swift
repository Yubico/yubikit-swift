import XCTest

final class UserVerificationTests: FidoUITestBase {

    /// Two UV misses with decrementing retry count, then the third attempt
    /// succeeds. Each miss transitions fingerprint → fingerprintRetry →
    /// user taps Try Again → back to fingerprint.
    func testRetryThenSuccess() {
        tapScenario("flow_uv_retry_then_success")
        assertFingerprintRetriesRemaining(2)
        app.buttons["retry_uv_button"].tap()
        assertFingerprintRetriesRemaining(1)
        app.buttons["retry_uv_button"].tap()
        expectSuccess()
    }

    /// UV retries hit 0; SDK throws `.uvBlocked` and FidoUI renders the
    /// locked panel with PIN+Cancel — gives the user an explicit "sensor
    /// locked" moment before they enter PIN.
    func testExhaustionFallsBackToPIN() {
        tapScenario("flow_uv_exhaustion_pin_fallback")
        assertFingerprintRetriesRemaining(2)
        app.buttons["retry_uv_button"].tap()
        assertFingerprintRetriesRemaining(1)
        app.buttons["retry_uv_button"].tap()
        assertElementExists(app.staticTexts["fingerprint_locked_title"], timeout: TestTimeouts.slow)
        app.buttons["use_pin_button"].tap()
        submitPIN("123456")
        expectSuccess()
    }

    /// One UV miss, user taps "Use PIN Instead" on the retry panel — no
    /// further UV retry is consumed by the decline. PIN succeeds.
    func testDeclineToPIN() {
        tapScenario("flow_uv_decline_to_pin")
        assertElementExists(app.staticTexts["fingerprint_retry_title"])
        app.buttons["use_pin_button"].tap()
        submitPIN("123456")
        expectSuccess()
    }

    /// UV-only authenticator (no PIN configured): each miss decrements the
    /// retry counter and the last surfaces `.uvBlocked` as a terminal
    /// error — Dismiss only, no Retry, no PIN fallback because there is
    /// nothing to fall back to.
    func testUVOnlyKeyExhaustionIsTerminal() {
        tapScenario("err_uv_blocked")
        assertFingerprintRetriesRemaining(2)
        app.buttons["retry_uv_button"].tap()
        assertFingerprintRetriesRemaining(1)
        app.buttons["retry_uv_button"].tap()
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["err_uv_blocked"], timeout: TestTimeouts.fast)
    }
}
