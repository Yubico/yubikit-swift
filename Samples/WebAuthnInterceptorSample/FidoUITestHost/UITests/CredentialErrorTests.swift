import XCTest

final class CredentialErrorTests: FidoUITestBase {

    func testAuthenticationNoCredentials() {
        tapScenario("auth_no_credentials")
        assertElementExists(app.staticTexts["error_title"])
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["auth_no_credentials"], timeout: TestTimeouts.fast)
    }

    func testRegistrationCredentialExcluded() {
        tapScenario("reg_credential_excluded")
        assertElementExists(app.staticTexts["error_title"])
        app.buttons["dismiss_button"].tap()
        assertElementExists(app.buttons["reg_credential_excluded"], timeout: TestTimeouts.fast)
    }
}
