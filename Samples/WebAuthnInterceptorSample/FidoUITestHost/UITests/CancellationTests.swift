import XCTest

final class CancellationTests: FidoUITestBase {

    func testCancelAtAuthenticationPIN() {
        tapScenario("auth_cancel_at_pin")
        assertElementExists(app.secureTextFields["pin_input_field"], timeout: TestTimeouts.fast)
        app.buttons["cancel_button"].tap()
        assertElementExists(app.buttons["auth_cancel_at_pin"], timeout: TestTimeouts.fast)
    }

    func testCancelAtRegistrationPIN() {
        tapScenario("reg_cancel_at_pin")
        assertElementExists(app.secureTextFields["pin_input_field"], timeout: TestTimeouts.fast)
        app.buttons["cancel_button"].tap()
        assertElementExists(app.buttons["reg_cancel_at_pin"], timeout: TestTimeouts.fast)
    }

    /// Two matching credentials → picker appears → user taps Cancel.
    func testCancelAtCredentialPicker() {
        tapScenario("auth_cancel_at_picker")
        assertElementExists(app.staticTexts["credential_picker_title"], timeout: TestTimeouts.slow)
        app.buttons["credential_picker_cancel_button"].tap()
        assertElementExists(app.buttons["auth_cancel_at_picker"], timeout: TestTimeouts.fast)
    }
}
