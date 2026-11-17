import Foundation
import Testing
import YubiKit

@testable import FidoUI

@Suite("FidoUI Presentation")
@MainActor
struct PresentationTests {
    @Test("A detached host fails before starting an authentication ceremony")
    func missingAnchor() async throws {
        let ui = FidoUI(presentationAnchor: { nil }, isPublicSuffix: { _ in false })
        do {
            _ = try await ui.getAssertion(
                .init(challenge: Data([1, 2, 3])),
                origin: WebAuthn.Origin("https://example.com")
            )
            Issue.record("Expected presentationUnavailable")
        } catch FidoUI.Error.presentationUnavailable {}
    }
}
