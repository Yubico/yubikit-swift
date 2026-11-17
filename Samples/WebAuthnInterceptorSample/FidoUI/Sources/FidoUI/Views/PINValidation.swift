import Foundation

enum PINValidationIssue: Equatable {
    case tooShort(minimumCodePoints: Int)
    case tooLong
    case mismatch

    var message: String {
        switch self {
        case .tooShort(let minimumCodePoints):
            String(localized: "PIN must be at least \(minimumCodePoints) characters")
        case .tooLong:
            String(localized: "PIN is too long. Use fewer characters.")
        case .mismatch:
            String(localized: "PINs don't match")
        }
    }

    var isError: Bool {
        if case .tooLong = self { return true }
        return false
    }
}

func pinValidationIssue(_ pin: String, minimumCodePoints: Int) -> PINValidationIssue? {
    let pin = normalizedPIN(pin)
    guard pin.unicodeScalars.count >= minimumCodePoints else {
        return .tooShort(minimumCodePoints: minimumCodePoints)
    }
    guard pin.utf8.count <= 63 else {
        return .tooLong
    }
    return nil
}

private func normalizedPIN(_ pin: String) -> String {
    pin.precomposedStringWithCanonicalMapping
}

func pinPairValidationIssue(
    newPIN: String,
    repeatPIN: String,
    minimumCodePoints: Int
) -> PINValidationIssue? {
    if !newPIN.isEmpty,
        let issue = pinValidationIssue(newPIN, minimumCodePoints: minimumCodePoints)
    {
        return issue
    }

    if !repeatPIN.isEmpty {
        if let issue = pinValidationIssue(repeatPIN, minimumCodePoints: 0) {
            return issue
        }
        if normalizedPIN(newPIN) != normalizedPIN(repeatPIN) {
            return .mismatch
        }
    }

    return nil
}
