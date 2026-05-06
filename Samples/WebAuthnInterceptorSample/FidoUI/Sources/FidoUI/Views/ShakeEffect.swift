import SwiftUI

struct ShakeEffect: GeometryEffect {
    var animatableData: CGFloat

    init(shakes: CGFloat) {
        self.animatableData = shakes
    }

    func effectValue(size: CGSize) -> ProjectionTransform {
        let amplitude: CGFloat = 30.0
        let decay: Double = 2.5
        let frequency: Double = 4.0

        let progress = Double(animatableData - floor(animatableData))
        let dampedAmplitude = amplitude * exp(-decay * progress)
        let translation = dampedAmplitude * sin(progress * .pi * frequency)

        return ProjectionTransform(
            CGAffineTransform(translationX: translation, y: 0)
        )
    }
}

extension View {
    func shake(trigger: Int) -> some View {
        modifier(ShakeModifier(trigger: trigger))
    }
}

private struct ShakeModifier: ViewModifier {
    let trigger: Int
    @State private var shakeAmount: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .modifier(ShakeEffect(shakes: shakeAmount))
            .onChange(of: trigger) {
                withAnimation(.easeOut(duration: 0.5)) {
                    shakeAmount += 1
                }
            }
    }
}
