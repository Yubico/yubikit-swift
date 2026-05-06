import Foundation

extension FidoUI {

    enum Strings {

        // MARK: - NFC system-sheet messages

        static func nfcAlertCreate(serviceName: String) -> String {
            String(localized: "Tap your YubiKey to create a passkey for \(serviceName)")
        }

        static func nfcAlertSignIn(serviceName: String) -> String {
            String(localized: "Tap your YubiKey to sign in to \(serviceName)")
        }

        static let nfcAlertSetPIN = String(localized: "Tap your YubiKey to set a PIN")

        static let nfcAlertChangePIN = String(localized: "Tap your YubiKey to change the PIN")

        // MARK: - NFC sheet success messages

        static let nfcSuccessRegistration = String(localized: "Passkey created")

        static let nfcSuccessAuthentication = String(localized: "Sign-in successful")

    }
}
