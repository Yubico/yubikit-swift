import XCTest

/// iOS NFC has its own PIN flow (out-of-band prefetch) covered by
/// `NFCPrefetchPINTests`.
final class PINEntryTests: FidoUITestBase {

    /// One wrong PIN, form re-arms with retry counter, correct PIN succeeds.
    /// Counterpart to `UserVerificationTests.testRetryThenSuccess` for the
    /// PIN side — the soft-block test below covers the terminal case but
    /// not successful recovery.
    func testWrongPINThenCorrect() {
        tapScenario("flow_pin_retry_then_success")
        submitPIN("wrong")
        assertPINRetriesRemaining(7)
        submitPIN("123456")
        expectSuccess()
    }

    /// Three consecutive misses trip the CTAP 2.1 soft block. The retry
    /// counter decrements 7 → 6 across the first two attempts; the third
    /// surfaces `.pinAuthBlocked` and the form does not re-arm — the
    /// terminal panel takes over with no Retry button.
    func testThreeMissesTripSoftBlock() {
        tapScenario("flow_progressive_pin_retries")
        submitPIN("wrong1")
        assertPINRetriesRemaining(7)
        submitPIN("wrong2")
        assertPINRetriesRemaining(6)
        submitPIN("wrong3")
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["flow_progressive_pin_retries"], timeout: TestTimeouts.fast)
    }

    /// Authenticator already in `.pinAuthBlocked` (powerCycleState=true,
    /// retries=2). First PIN submission throws straight to the terminal
    /// panel; user must reinsert.
    func testPINAuthBlockedIsTerminal() {
        tapScenario("err_pin_auth_blocked")
        submitPIN("123456")
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["err_pin_auth_blocked"], timeout: TestTimeouts.fast)
    }
}
