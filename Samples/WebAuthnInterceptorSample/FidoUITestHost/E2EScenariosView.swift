// FidoUI end-to-end scenarios. Each scenario runs the real FidoUI stack
// (Connection lifecycle + Presenter + PanelView) against mocked WebAuthn +
// PIN-setup backends, so every UI path — ceremony, retries, setup recovery,
// UV fallback, error panels, cancellation — can be exercised deterministically
// with no real YubiKey. The FidoUITestHost app launches straight into this view.
//
// The catalog is grouped by the FidoUI subsystem each scenario exercises:
// PIN setup recovery, force-PIN-change, inline PIN entry, user verification,
// ceremony shape (no-PIN / touch / multi-ceremony / reconnect), cancellation
// paths, and credential-side errors. Each section maps 1:1 to a test class
// in `FidoUITestHost/UITests` and to a `Scenarios+<topic>.swift` file
// holding its runner functions.

import FidoUI
import SwiftUI

@testable import YubiKit

struct E2EScenariosView: View {
    @State private var status = ScenarioStatus()

    // ScrollView + VStack (not List) so every scenario row is always in the
    // accessibility tree — iOS `List` is lazy and hides off-screen rows from
    // XCUITest queries, making `waitForExistence` fail for bottom scenarios.
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                section("PIN setup recovery", Scenario.pinSetupRecovery)
                section("Force PIN change", Scenario.forcePINChange)
                section("PIN entry", Scenario.pinEntry)
                section("User verification", Scenario.userVerification)
                section("Ceremony shape", Scenario.ceremonyShape)
                section("Cancellation", Scenario.cancellation)
                section("Credential errors", Scenario.credentialErrors)
            }
            .padding(.vertical, 8)
        }
    }

    private func section(_ title: String, _ scenarios: [Scenario]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 16)
                .padding(.top, 12)
                .padding(.bottom, 4)
            ForEach(scenarios) { scenario in
                ScenarioRow(scenario: scenario, status: status) {
                    await status.run(scenario)
                }
                .accessibilityIdentifier(scenario.id)
                Divider().padding(.leading, 16)
            }
        }
    }
}

/// Tracks per-scenario outcome so the catalog can surface "completed" vs
/// "failed" without launching XCUITest. Misconfigured mocks (e.g. an
/// unhandled `try` from the scenario function) show as failed instead of
/// silently appearing to succeed.
@Observable
@MainActor
final class ScenarioStatus {
    enum Outcome: Sendable, Equatable {
        case running
        case completed
        case failed(String)
    }

    var byId: [String: Outcome] = [:]

    func run(_ scenario: Scenario) async {
        byId[scenario.id] = .running
        let outcome = await scenario.run()
        byId[scenario.id] = outcome
    }
}

private struct ScenarioRow: View {
    let scenario: Scenario
    let status: ScenarioStatus
    let run: @MainActor () async -> Void

    var body: some View {
        Button {
            Task { await run() }
        } label: {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(scenario.title)
                        .font(.body)
                        .foregroundStyle(.primary)
                        .multilineTextAlignment(.leading)
                    Text(scenario.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 8)
                outcomeIcon
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var outcomeIcon: some View {
        switch status.byId[scenario.id] {
        case nil:
            Image(systemName: "chevron.right")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)
                .accessibilityHidden(true)
        case .running:
            ProgressView().controlSize(.small)
        case .completed:
            Image(systemName: "checkmark.circle.fill")
                .font(.callout)
                .foregroundStyle(.green)
                .accessibilityLabel("Completed")
        case .failed(let message):
            Image(systemName: "xmark.octagon.fill")
                .font(.callout)
                .foregroundStyle(.red)
                .accessibilityLabel("Failed: \(message)")
        }
    }
}

// MARK: - Scenario catalog

struct Scenario: Identifiable {
    let id: String
    let title: String
    let summary: String
    let run: @MainActor () async -> ScenarioStatus.Outcome
}

extension Scenario {

    static let pinSetupRecovery: [Scenario] = [
        Scenario(
            id: "flow_first_time_setup",
            title: "First-time setup",
            summary: "Fresh key → pinNotSet → createPIN → setPIN → retry ceremony → success.",
            run: Runner.flowFirstTimeSetup
        ),
        Scenario(
            id: "flow_setup_transient_connect_fail",
            title: "Transient connect fail",
            summary: "createPIN → setPIN session drops; createPIN re-arms with retry message → success.",
            run: Runner.flowSetupTransientConnectFail
        ),
        Scenario(
            id: "err_setup_permanent_failure",
            title: "Permanent host failure",
            summary: "createPIN → setPIN throws non-CTAP error → fatal, no retry loop.",
            run: Runner.errSetupPermanentFailure
        ),
    ]

    static let forcePINChange: [Scenario] = [
        Scenario(
            id: "flow_force_pin_change",
            title: "Force PIN change",
            summary: "Auth → forcePinChange detected upfront → changePIN → retry ceremony → success.",
            run: Runner.flowForcePinChange
        ),
        Scenario(
            id: "flow_force_pin_change_complexity",
            title: "Complexity reject",
            summary: "First new PIN rejected; current-PIN field must stay pre-filled on retry.",
            run: Runner.flowForcePinChangeComplexityThenSuccess
        ),
        Scenario(
            id: "flow_force_pin_change_wrong_current",
            title: "Wrong current PIN",
            summary: "First current PIN wrong; form re-arms with 'incorrect' message; correct PIN succeeds.",
            run: Runner.flowForcePinChangeWrongCurrent
        ),
    ]

    static let pinEntry: [Scenario] = [
        Scenario(
            id: "flow_pin_retry_then_success",
            title: "Wrong PIN once → correct",
            summary: "Form re-arms with retry counter (7), correct PIN succeeds.",
            run: Runner.flowPINRetryThenSuccess
        ),
        Scenario(
            id: "flow_progressive_pin_retries",
            title: "Wrong PIN ×3 → soft block",
            summary: "Retry count decrements 7 → 6, 3rd miss trips pinAuthBlocked — reinsert required.",
            run: Runner.flowProgressivePINRetries
        ),
        Scenario(
            id: "err_pin_auth_blocked",
            title: "PIN auth blocked",
            summary: "Too many attempts this power cycle; reinsert required.",
            run: Runner.errPINAuthBlocked
        ),
        Scenario(
            id: "auth_validates_submitted_pin",
            title: "Validates submitted PIN",
            summary: "Mock rejects any PIN other than 123456; success proves the typed value reached the backend.",
            run: Runner.authValidatesSubmittedPIN
        ),
    ]

    static let userVerification: [Scenario] = [
        Scenario(
            id: "flow_uv_retry_then_success",
            title: "UV miss ×2 then success",
            summary: "Fingerprint miss, retry panel, try again — 3rd attempt succeeds.",
            run: Runner.flowUVRetryThenSuccess
        ),
        Scenario(
            id: "flow_uv_exhaustion_pin_fallback",
            title: "UV exhaustion → PIN fallback",
            summary: "UV retries hit 0 → locked panel → Use PIN → success.",
            run: Runner.flowUVExhaustionPINFallback
        ),
        Scenario(
            id: "flow_uv_decline_to_pin",
            title: "UV miss → Use PIN Instead",
            summary: "Miss once, user declines UV, PIN accepted.",
            run: Runner.flowUVDeclineToPIN
        ),
        Scenario(
            id: "err_uv_blocked",
            title: "UV blocked (bio-only key)",
            summary: "UV-only authenticator, all retries exhausted → fatal lock.",
            run: Runner.errUVBlocked
        ),
    ]

    static let ceremonyShape: [Scenario] = [
        Scenario(
            id: "auth_no_pin",
            title: "Authenticate without PIN",
            summary: "UP-only authenticator; straight to touch prompt.",
            run: Runner.authNoPIN
        ),
        Scenario(
            id: "flow_touch_required",
            title: "Touch required mid-flow",
            summary: "Stream emits .processing then .waitingForUser before finishing.",
            run: Runner.flowTouchRequired
        ),
        Scenario(
            id: "flow_register_then_auth",
            title: "Register, then sign in",
            summary: "Register a passkey, dismiss success, authenticate via picker.",
            run: Runner.flowRegisterThenAuth
        ),
        Scenario(
            id: "flow_connection_drop_mid_ceremony",
            title: "Connection drop mid-ceremony",
            summary: "Stream errors with authenticatorNotAvailable; reconnect bridge → retry → success.",
            run: Runner.flowConnectionDropMidCeremony
        ),
    ]

    static let cancellation: [Scenario] = [
        Scenario(
            id: "auth_cancel_at_pin",
            title: "Cancel at auth PIN prompt",
            summary: "Taps Cancel on the PIN panel during authentication; sheet dismisses.",
            run: Runner.authCancelAtPIN
        ),
        Scenario(
            id: "reg_cancel_at_pin",
            title: "Cancel at registration PIN prompt",
            summary: "Taps Cancel on the PIN panel during registration; sheet dismisses.",
            run: Runner.regCancelAtPIN
        ),
        Scenario(
            id: "auth_cancel_at_picker",
            title: "Cancel at credential picker",
            summary: "Two matching credentials; user cancels the picker.",
            run: Runner.authCancelAtPicker
        ),
    ]

    static let credentialErrors: [Scenario] = [
        Scenario(
            id: "auth_no_credentials",
            title: "No credentials (auth)",
            summary: "Authenticator reports no matching credentials; error panel.",
            run: Runner.authNoCredentials
        ),
        Scenario(
            id: "reg_credential_excluded",
            title: "Credential already registered",
            summary: "Authenticator rejects: a passkey already exists for this user.",
            run: Runner.regCredentialExcluded
        ),
    ]
}

/// Namespace for all scenario runner functions. Split across Scenarios+* files.
@MainActor
enum Runner {

    /// Wraps a `FidoUI.makeCredential` call so the scenario surfaces a
    /// terminal outcome to the catalog. `.cancelled` is treated as completed
    /// — user-driven cancel is a valid scenario endpoint, not a failure.
    /// Origin is fixed to `https://example.com` for all scenarios; the
    /// mock backend doesn't validate against it.
    static func runMakeCredential(
        _ fido: FidoUI,
        options: WebAuthn.Registration.Options,
        serviceName: String? = nil
    ) async -> ScenarioStatus.Outcome {
        do {
            let origin = try WebAuthn.Origin("https://example.com")
            _ = try await fido.makeCredential(options, origin: origin, serviceName: serviceName)
            return .completed
        } catch FidoUI.Error.cancelled {
            return .completed
        } catch {
            return .failed("\(error)")
        }
    }

    static func runGetAssertion(
        _ fido: FidoUI,
        options: WebAuthn.Authentication.Options,
        serviceName: String? = nil
    ) async -> ScenarioStatus.Outcome {
        do {
            let origin = try WebAuthn.Origin("https://example.com")
            _ = try await fido.getAssertion(options, origin: origin, serviceName: serviceName)
            return .completed
        } catch FidoUI.Error.cancelled {
            return .completed
        } catch {
            return .failed("\(error)")
        }
    }
}
