@testable import FidoUI

/// Swift 6 forbids mutating captured `var` from inside a `@Sendable` closure.
/// Test observations are single-threaded-by-convention under `.serialized`, so
/// a reference-typed box with an unchecked Sendable conformance is the cheapest
/// way to keep the existing test shape without redesigning each scenario.
final class Box<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

/// Polls the model's panel until `predicate` returns true (up to ~200 yields).
/// Use when the previous iteration may have left the panel in the kind you're
/// waiting for, so a kind-only wait would return immediately against the stale
/// state — match on a value (e.g. `retries != nil`) that can only appear once
/// the new panel has been installed.
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
