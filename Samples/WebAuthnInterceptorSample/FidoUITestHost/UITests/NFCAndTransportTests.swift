import XCTest

// Cover both PIN-first and key-first NFC flows with the mock transport.
#if os(iOS)
final class NFCPrefetchPINTests: FidoUITestBase {

    /// Forces the mock transport into NFC mode for every scenario this
    /// suite runs — the picker times out, commits to NFC, and exercises
    /// the prefetch-PIN flow. Wired-flow coverage on iOS shares classes
    /// with macOS (no launch arg, default `.wired`).
    override var extraLaunchArguments: [String] { ["--mock-nfc", "--pin-prioritized"] }

    /// Real PIN-protected key (`clientPin=true`). User types the correct
    /// PIN at the prefetch form; the cached value is consumed inside the
    /// ceremony body. The mock backend rejects anything other than
    /// "123456", so reaching success proves the typed value flowed
    /// through `Authorization.providePIN` → `getPinUVTokenUpdates` rather
    /// than being dropped or replayed.
    func testSubmittedPINReachesBackend() {
        tapScenario("auth_validates_submitted_pin")
        submitPIN("123456")
        expectSuccess()
    }

    /// Wrong PIN at prefetch, ceremony surfaces `.pinRejected`, the
    /// prefetch panel re-arms with the retry counter, correct PIN
    /// succeeds. Regression test for the iOS PIN re-prompt path: before
    /// `handleClientError` propagated `.pinRejected`, the cached bad PIN
    /// auto-resubmitted on Retry and the user couldn't recover.
    func testWrongPINThenCorrect() {
        tapScenario("flow_pin_retry_then_success")
        submitPIN("wrong")
        assertPINRetriesRemaining(7)
        submitPIN("123456")
        expectSuccess()
    }

    /// User taps Cancel on the prefetch PIN form before submitting. The
    /// ceremony short-circuits (no session ever acquired) and the catalog
    /// returns immediately.
    func testCancelAtPrefetchPIN() {
        tapScenario("auth_cancel_at_pin")
        assertElementExists(app.secureTextFields["pin_input_field"])
        app.buttons["cancel_button"].tap()
        assertElementExists(app.images["Completed"], timeout: TestTimeouts.fast)
    }

    func testWaitForUSBSuppressesAutomaticNFC() {
        tapScenario("auth_no_pin")
        assertElementExists(app.buttons["waiting_for_key_wait_usb_button"])
        app.buttons["waiting_for_key_wait_usb_button"].tap()
        XCTAssertTrue(app.buttons["waiting_for_key_cancel_button"].waitForExistence(timeout: 5), app.debugDescription)
        XCTAssertFalse(app.secureTextFields["pin_input_field"].waitForExistence(timeout: 4))
        app.buttons["waiting_for_key_cancel_button"].tap()
        assertElementExists(app.images["Completed"], timeout: TestTimeouts.fast)
    }

    /// PIN auth blocked for this power cycle (retries=2, powerCycleState=true).
    /// Terminal panel treatment — Dismiss only, no Retry. Covers the
    /// `handleClientError` terminal-error path on the iOS prefetch-PIN flow.
    func testPINAuthBlockedIsTerminal() {
        tapScenario("err_pin_auth_blocked")
        submitPIN("123456")
        assertElementExists(app.staticTexts["error_title"], timeout: TestTimeouts.slow)
        XCTAssertFalse(app.buttons["retry_button"].exists)
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["err_pin_auth_blocked"], timeout: TestTimeouts.fast)
    }
}
final class NFCKeyFirstTests: FidoUITestBase {
    override var extraLaunchArguments: [String] { ["--mock-nfc"] }

    func testNoPINOrUVDoesNotPrompt() {
        tapScenario("auth_no_pin")
        expectSuccess()
    }

    func testPINRequestedAfterFirstScan() {
        tapScenario("auth_validates_submitted_pin")
        submitPIN("123456")
        expectSuccess()
    }

    func testFirstTimeSetupSkipsPrefetch() {
        tapScenario("flow_first_time_setup")
        assertElementExists(app.staticTexts["create_pin_title"])
        submitNewPIN("123456")
        assertElementExists(app.staticTexts["pin_created_title"])
        app.buttons["pin_created_continue_button"].tap()
        XCTAssertTrue(app.staticTexts["success_title"].waitForExistence(timeout: 10), app.debugDescription)
    }
}

final class TransportChoiceTests: FidoUITestBase {
    override var extraLaunchArguments: [String] { ["--slow-wired", "--pin-prioritized"] }

    func testSlowWiredConnectionStaysVisibleAndCompletes() {
        tapScenario("auth_no_pin")
        assertElementExists(app.staticTexts["connecting_to_key_title"])
        XCTAssertTrue(app.buttons["waiting_for_key_use_nfc_button"].exists)
        expectSuccess()
    }

    func testChooseNFCWhileWiredIsConnecting() {
        tapScenario("auth_no_pin")
        assertElementExists(app.buttons["waiting_for_key_use_nfc_button"])
        app.buttons["waiting_for_key_use_nfc_button"].tap()
        submitPIN("123456")
        expectSuccess()
    }

    func testCancelWhileWiredIsConnecting() {
        tapScenario("auth_no_pin")
        assertElementExists(app.buttons["waiting_for_key_cancel_button"])
        app.buttons["waiting_for_key_cancel_button"].tap()
        assertElementExists(app.images["Completed"], timeout: TestTimeouts.fast)
    }
}
#endif
