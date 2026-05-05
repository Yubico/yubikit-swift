import XCTest

final class ForcePINChangeTests: FidoUITestBase {

    func testHappyPath() {
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

    func testComplexityRejectThenSuccess() {
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
    func testWrongCurrentPINThenSuccess() {
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
}
