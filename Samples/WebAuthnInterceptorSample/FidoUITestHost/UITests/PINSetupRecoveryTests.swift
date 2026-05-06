import XCTest

final class PINSetupRecoveryTests: FidoUITestBase {

    func testFirstTimeSetup() {
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

    /// applySetup's session acquire throws transient on the first attempt
    /// after the user submits a new PIN. The createPIN form re-arms with the
    /// failure message; resubmitting the same PIN succeeds.
    func testTransientConnectFailReArmsCreatePIN() {
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
        // pre-filled — tap Continue to consume it (mirrors `testFirstTimeSetup`).
        assertElementExists(app.secureTextFields["pin_input_field"])
        app.buttons["continue_button"].tap()
        expectSuccess()
    }

    /// Regression: a permanent host-side failure during PIN setup recovery
    /// must surface as a terminal error panel, not loop the createPIN form.
    func testPermanentHostFailureIsFatal() {
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
