@testable import FidoUI

/// Reference-typed mutable cell — Swift 6 forbids mutating captured `var`
/// from a `@Sendable` closure, and tests are serialized-by-convention.
final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

/// Match on a value (e.g. `retries != nil`) when a kind-only wait would
/// race against a stale panel left by the previous iteration.
@MainActor
func waitForPanel(
    _ model: FidoUI.PanelModel,
    matching predicate: (FidoUI.PanelModel.Panel) -> Bool
) async {
    for _ in 0..<200 {
        if predicate(model.panel) { return }
        await Task.yield()
    }
}

@MainActor
func waitForPanel(
    _ model: FidoUI.PanelModel,
    kind: FidoUI.PanelModel.PanelKind
) async {
    await waitForPanel(model) { $0.kind == kind }
}
