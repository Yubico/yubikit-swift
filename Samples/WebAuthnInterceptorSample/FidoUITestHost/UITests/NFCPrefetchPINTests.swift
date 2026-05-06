import XCTest

// iOS NFC ceremony shape diverges from the wired path: `runCeremony` calls
// `collectPrefetchedPIN` upfront after committing to NFC
// (Presenter+Ceremony.swift:75-78), so every NFC ceremony begins with a
// PIN form before any session is acquired. This file covers the scenarios
// where that flow is coherent on iOS — i.e. real PIN-protected
// authenticators where typing a PIN upfront makes sense.
//
// Scenarios deliberately NOT covered here:
//
// - `auth_no_pin`, `auth_no_credentials`, `flow_touch_required`,
//   `flow_connection_drop_mid_ceremony`, `flow_register_then_auth`,
//   `auth_cancel_at_picker`:
//   clientPin=false on the mock, but iOS still asks for a PIN at prefetch.
//   The user types a PIN that's never used. Functional but user-hostile;
//   needs a `runCeremony` change to skip prefetch when the authenticator
//   has no PIN before these are worth testing.
//
// - `flow_progressive_pin_retries`: works on iOS now that `.pinRejected`
//   propagates to `runCeremony` and re-prompts via `collectPrefetchedPIN`.
//   Not covered yet — needs three prefetch sheets and a retries-on-second-
//   prefetch assertion that the helpers below don't model. The simpler
//   `flow_pin_retry_then_success` covers the same `.pinRejected` recovery
//   path with one retry.
//
// - `flow_first_time_setup`, `flow_force_pin_change*`,
//   `flow_setup_transient_connect_fail`, `err_setup_permanent_failure`:
//   prefetch PIN fires before runCeremony's body learns about the recovery
//   path, so the user types two PINs (prefetch + create/change). Awkward
//   but functional; could be tested once ergonomics are settled.
//
// - `flow_uv_*`, `err_uv_blocked`: UV path's interaction with the prefetch
//   PIN cache isn't verified end-to-end on iOS yet.
#if os(iOS)
final class NFCPrefetchPINTests: FidoUITestBase {

    /// Forces the mock transport into NFC mode for every scenario this
    /// suite runs — the picker times out, commits to NFC, and exercises
    /// the prefetch-PIN flow. Wired-flow coverage on iOS shares classes
    /// with macOS (no launch arg, default `.wired`).
    override var extraLaunchArguments: [String] { ["--mock-nfc"] }

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
        assertElementExists(app.buttons["auth_cancel_at_pin"], timeout: TestTimeouts.fast)
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
#endif
