import XCTest

/// Shared XCUITest base for the macOS and iOS E2E flow suites. Holds the
/// app launch boilerplate, the per-element assertion helpers, and the
/// platform-portable text predicate used to absorb SwiftUI's
/// AXLabel-vs-AXValue divergence.
class FidoUITestBase: XCTestCase {

    var app: XCUIApplication!

    /// Subclasses override to add launch arguments before the app
    /// launches — e.g. `["--mock-nfc"]` to make `defaultMockTransport`
    /// resolve to `.nfc` for the entire suite.
    var extraLaunchArguments: [String] { [] }

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments.append(contentsOf: extraLaunchArguments)
        app.launch()
    }

    // MARK: - Element waits

    /// Asserts the element appears within `timeout`. Replaces the noisy
    /// `XCTAssertTrue(x.waitForExistence(timeout: 5))` pattern.
    func assertElementExists(
        _ element: XCUIElement,
        timeout: TimeInterval = TestTimeouts.normal,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        XCTAssertTrue(
            element.waitForExistence(timeout: timeout),
            "Element did not appear within \(timeout)s",
            file: file,
            line: line
        )
    }

    /// `XCUIElement.waitForExistence` waits for app idle before each poll,
    /// which times out on panels that animate continuously
    /// (`.repeatForever`). Polling `.exists` directly bypasses the idle
    /// wait. Use only for elements behind a `.repeatForever` animation.
    func pollForExistence(
        _ element: XCUIElement,
        timeout: TimeInterval = TestTimeouts.slow,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !element.exists && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }
        XCTAssertTrue(
            element.exists,
            "Element did not appear within \(timeout)s",
            file: file,
            line: line
        )
    }

    // MARK: - Scenario picker

    /// Catalog spans more rows than fit in the test window on macOS. macOS
    /// XCUITest doesn't auto-scroll on `.tap()`, so a row below the fold is
    /// recognised in the AX tree (`exists` is true) but the click lands on
    /// the surrounding ScrollView. Scroll explicitly until the row is
    /// hittable, then tap.
    func tapScenario(_ id: String) {
        let button = app.buttons[id].firstMatch
        assertElementExists(button, timeout: TestTimeouts.fast)
        scrollIntoView(button)
        button.tap()
    }

    private func scrollIntoView(_ element: XCUIElement) {
        guard !element.isHittable else { return }
        let scrollView = app.scrollViews.firstMatch
        guard scrollView.exists else { return }
        // Each `isHittable` query and each scroll round-trips to the
        // runner; visible delay scales with the iteration count. Send a
        // large first scroll that clears the entire catalog viewport in
        // one go, then only re-check + top-up if still off-screen.
        #if os(macOS)
        // Negative deltaY pushes content up (= scrolls toward bottom).
        scrollView.scroll(byDeltaX: 0, deltaY: -2000)
        #else
        scrollView.swipeUp()
        #endif
        var attempts = 0
        while !element.isHittable && attempts < 4 {
            #if os(macOS)
            scrollView.scroll(byDeltaX: 0, deltaY: -600)
            #else
            scrollView.swipeUp()
            #endif
            attempts += 1
        }
    }

    // MARK: - PIN entry

    /// Backspace stream used to clear a secure field before typing into it.
    /// Length-agnostic — `XCUIElement.value` for `SecureField` is unreliable
    /// (masked or nil depending on platform), so we just blast more
    /// backspaces than any plausible PIN length. Extra backspaces on an empty
    /// field are no-ops.
    private static let clearSecureField = String(
        repeating: XCUIKeyboardKey.delete.rawValue,
        count: 32
    )

    func submitPIN(_ pin: String) {
        let pinField = app.secureTextFields["pin_input_field"]
        assertElementExists(pinField)
        pinField.tap()
        pinField.typeText(Self.clearSecureField + pin)
        app.buttons["continue_button"].tap()
    }

    func typePIN(_ pin: String, into identifier: String) {
        let field = app.secureTextFields[identifier]
        assertElementExists(field, timeout: TestTimeouts.fast)
        field.tap()
        field.typeText(Self.clearSecureField + pin)
    }

    func submitNewPIN(_ pin: String) {
        typePIN(pin, into: "new_pin_input")
        typePIN(pin, into: "repeat_pin_input")
        app.buttons["create_pin_button"].tap()
    }

    // MARK: - Outcomes

    func expectSuccess() {
        assertElementExists(app.staticTexts["success_title"], timeout: TestTimeouts.slow)
    }

    /// "Incorrect PIN. N attempts remaining." — assert the pin_error_message
    /// static text contains the expected count.
    func assertPINRetriesRemaining(
        _ n: Int,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        assertLabelContainsRetries(identifier: "pin_error_message", n: n, file: file, line: line)
    }

    /// "N attempts remaining" under the fingerprint retry panel.
    func assertFingerprintRetriesRemaining(
        _ n: Int,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        assertLabelContainsRetries(
            identifier: "fingerprint_retry_retries_remaining",
            n: n,
            file: file,
            line: line
        )
    }

    func assertLabelContainsRetries(
        identifier: String,
        n: Int,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        // Mirror retriesText(_:): singular "1 attempt remaining" / plural
        // "N attempts remaining".
        let expected = n == 1 ? "1 attempt remaining" : "\(n) attempts remaining"
        let exp = expectation(
            for: predicateForSwiftUIText(expected),
            evaluatedWith: app.staticTexts[identifier]
        )
        XCTAssertEqual(
            XCTWaiter().wait(for: [exp], timeout: TestTimeouts.slow),
            .completed,
            "Expected label \(identifier) to contain \"\(expected)\"",
            file: file,
            line: line
        )
    }

    /// SwiftUI `Text` content lands in AXValue on macOS (the explicit
    /// `.accessibilityLabel` is also wrapped there: "Error: …") and in
    /// AXLabel on iOS. Match either so the same predicate works on both.
    func predicateForSwiftUIText(_ content: String) -> NSPredicate {
        NSPredicate(format: "value CONTAINS %@ OR label CONTAINS %@", content, content)
    }
}

/// Centralized timeouts so test bodies don't sprinkle magic numbers.
/// `fast` is for cheap UI state transitions; `normal` is the default for
/// form/field appearance; `slow` is for ceremony streams and async retries.
enum TestTimeouts {
    static let fast: TimeInterval = 3
    static let normal: TimeInterval = 5
    static let slow: TimeInterval = 10
}
