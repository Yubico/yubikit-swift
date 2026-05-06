#if DEBUG
import Foundation

extension FidoUI.PanelModel {
    static func preview(
        _ panel: Panel,
        operation: Operation = .registration,
        serviceName: String = "example.com"
    ) -> FidoUI.PanelModel {
        let model = FidoUI.PanelModel()
        model.panel = panel
        model.operation = operation
        model.serviceName = serviceName
        return model
    }
}
#endif
