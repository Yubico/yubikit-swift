// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import CommonCrypto
import Foundation

private let hotpCode: UInt8 = 0x10
private let totpCode: UInt8 = 0x20

extension OATHSession {

    /// Errors that can occur when creating credential templates from URLs.
    public enum CredentialTemplateError: Error {
        /// The URL is missing the required scheme (e.g., otpauth).
        case missingScheme
        /// The credential name is missing from the URL.
        case missingName
        /// The secret key is missing from the URL parameters.
        case missingSecret
        /// Failed to parse the credential type (HOTP/TOTP) from the URL.
        case parseType
        /// Failed to parse the hash algorithm from the URL parameters.
        case parseAlgorithm
    }

    /// The type of OATH credential (HOTP or TOTP).
    public enum CredentialType: CustomStringConvertible, Sendable {

        case HOTP(counter: UInt32 = 0)
        case TOTP(period: TimeInterval = 30)

        public var code: UInt8 {
            switch self {
            case .HOTP:
                return hotpCode
            case .TOTP:
                return totpCode
            }
        }

        static public func isHOTP(_ code: UInt8) -> Bool {
            code == hotpCode
        }

        static public func isTOTP(_ code: UInt8) -> Bool {
            code == totpCode
        }

        public var period: TimeInterval? {
            switch self {
            case .HOTP(counter: _):
                return nil
            case .TOTP(let period):
                return period
            }
        }

        public var counter: UInt32? {
            switch self {
            case .HOTP(let counter):
                return counter
            case .TOTP(period: _):
                return nil
            }
        }

        public var description: String {
            switch self {
            case .HOTP(let counter):
                return "HOTP(\(counter))"
            case .TOTP(let period):
                return "TOTP(\(period))"
            }
        }
    }

    /// Hash algorithms supported for OATH credentials.
    public enum HashAlgorithm: UInt8, Sendable {
        /// SHA-1 hash algorithm.
        case SHA1 = 0x01
        /// SHA-256 hash algorithm.
        case SHA256 = 0x02
        /// SHA-512 hash algorithm.
        case SHA512 = 0x03
    }

    /// A reference to an OATH Credential stored on a YubiKey.
    public struct Credential: Sendable, Identifiable, CustomStringConvertible {

        /// Device ID of the YubiKey.
        public let deviceId: String

        /// The ID of a Credential which is used to identify it to the YubiKey.
        public let id: Data

        /// OATH type of the credential (TOTP or HOTP).
        public let type: OATHSession.CredentialType

        /// Hash algorithm used by the credential (SHA1, SHA256 or SHA512).
        public let hashAlgorithm: OATHSession.HashAlgorithm?

        /// The name of the account (typically a username or email address).
        public let name: String

        /// The name of the Credential issuer (e.g. Google, Amazon, Facebook, etc.)
        public let issuer: String?

        /// Label of the Credential. Will return `issuer:name` if issuer is set, otherwise `name`.
        public var label: String {
            var label = ""
            // If type returns a period it's a TOTP credential
            if let period = type.period, period != oathDefaultPeriod {
                label.append("\(String(format: "%.0f", period))/")
            }
            if let issuer {
                label.append("\(issuer):")
            }
            label.append(name)
            return label
        }

        /// Whether or not the Credential requires touch. This value is always false when using ``listCredentials()``.
        public var requiresTouch: Bool

        public var description: String {
            "Credential(type: \(type), label:\(label), algorithm: \(hashAlgorithm.debugDescription)"
        }

        internal init(
            deviceId: String,
            id: Data,
            type: OATHSession.CredentialType,
            hashAlgorithm: OATHSession.HashAlgorithm? = nil,
            name: String,
            issuer: String?,
            requiresTouch: Bool
        ) {
            self.deviceId = deviceId
            self.id = id
            self.type = type
            self.hashAlgorithm = hashAlgorithm
            self.name = name
            self.issuer = issuer
            self.requiresTouch = requiresTouch
        }
    }

    internal struct CredentialIdParser {

        let account: String
        let issuer: String?
        let period: TimeInterval?

        init?(data: Data) {
            // "period/issuer:account"
            let periodIssuerAndAccount = #/^(?<period>\d+)\/(?<issuer>.+):(?<account>.+)$/#
            // "issuer:account"
            let issuerAndAccount = #/^(?<issuer>.+):(?<account>.+)$/#
            // "period/account"
            let periodAndAccount = #/^(?<period>\d+)\/(?<account>.+)$/#

            guard let id = String(data: data, encoding: .utf8) else { return nil }

            if let match = id.firstMatch(of: periodIssuerAndAccount) {
                period = TimeInterval(String(match.period))
                issuer = String(match.issuer)
                account = String(match.account)
            } else if let match = id.firstMatch(of: issuerAndAccount) {
                period = nil
                issuer = String(match.issuer)
                account = String(match.account)
            } else if let match = id.firstMatch(of: periodAndAccount) {
                period = TimeInterval(String(match.period))
                issuer = nil
                account = String(match.account)
            } else {
                period = nil
                issuer = nil
                account = id
            }
        }
    }

    /// A one-time OATH code, calculated from a ``Credential`` stored in a YubiKey.
    public struct Code: Identifiable, CustomStringConvertible, Sendable {

        public var description: String {
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "HH:mm:ss"
            return
                "Code(\(code), validFrom:\(dateFormatter.string(from: validFrom)), validTo:\(dateFormatter.string(from: validTo))"
        }

        public let id = UUID()

        /// String representation of the code, typically a 6-8 digit code.
        public let code: String

        /// The date this code will be valid from.
        public var validFrom: Date {
            switch credentialType {
            case .HOTP(_):
                return Date()
            case .TOTP(let period):
                return Date(
                    timeIntervalSince1970: timestamp.timeIntervalSince1970
                        - timestamp.timeIntervalSince1970.truncatingRemainder(dividingBy: period)
                )
            }
        }

        /// The date this code ends being valid.
        public var validTo: Date {
            switch credentialType {
            case .HOTP(_):
                return validFrom.addingTimeInterval(.infinity)
            case .TOTP(let period):
                return validFrom.addingTimeInterval(period)
            }
        }

        internal init(code: String, timestamp: Date, credentialType: CredentialType) {
            self.code = code
            self.timestamp = timestamp
            self.credentialType = credentialType
        }

        private let timestamp: Date
        private let credentialType: CredentialType

    }

    internal struct CredentialIdentifier {
        static func identifier(name: String, issuer: String?, type: OATHSession.CredentialType) -> String {
            let key: String
            if let issuer {
                key = "\(issuer):\(name)"
            } else {
                key = name
            }
            if case let .TOTP(period) = type {
                if period != oathDefaultPeriod {
                    return "\(String(format: "%.0f", period))/\(key)"
                } else {
                    return key
                }
            } else {
                return key
            }
        }
    }

    /// Template object holding all required information to add a new ``Credential`` to a YubiKey.
    public struct CredentialTemplate {

        private static let minSecretLenght = 14
        public let type: CredentialType
        public let algorithm: HashAlgorithm
        public let secret: Data
        public let issuer: String?
        public let name: String
        public let digits: UInt8
        public var requiresTouch: Bool

        /// Credential identifier, as used to identify it on a YubiKey.
        ///
        /// The Credential ID is calculated based on the combination of the issuer, the name, and (for TOTP credentials) the validity period.
        public var identifier: String {
            CredentialIdentifier.identifier(name: name, issuer: issuer, type: type)
        }

        /// Creates a CredentialTemplate by parsing a [otpauth:// URI](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
        /// - Parameters:
        ///   - url: The otpauth:// URI to parse.
        ///   - skipValidation: Set to true to skip input validation when parsing the uri.
        public init(withURL url: URL, skipValidation: Bool = false) throws {
            guard url.scheme == "otpauth" else { throw CredentialTemplateError.missingScheme }

            var issuer: String?
            var name: String = ""
            if !skipValidation {
                guard url.pathComponents.count > 1 else { throw CredentialTemplateError.missingName }
                name = url.pathComponents[1]
                if name.contains(":") {
                    let components = name.components(separatedBy: ":")
                    name = components[1]
                    issuer = components[0]
                } else {
                    issuer = url.queryValueFor(key: "issuer")
                }
            }

            let type = try OATHSession.CredentialType(fromURL: url)

            let algorithm = try OATHSession.HashAlgorithm(fromUrl: url) ?? .SHA1

            let digits: UInt8
            if let digitsString = url.queryValueFor(key: "digits"), let parsedDigits = UInt8(digitsString) {
                digits = parsedDigits
            } else {
                digits = 6
            }

            guard let secret = url.queryValueFor(key: "secret")?.base32DecodedData else {
                throw CredentialTemplateError.missingSecret
            }

            self.init(type: type, algorithm: algorithm, secret: secret, issuer: issuer, name: name, digits: digits)
        }

        /// Creates a CredentialTemplate.
        /// - Parameters:
        ///   - type: OATH type of the credential (TOTP or HOTP).
        ///   - algorithm: Hash algorithm used by the credential (SHA1, SHA256 or SHA512).
        ///   - secret: Secret key of the credential, in raw bytes (__not__ Base32 encoded)
        ///   - issuer: Name of the credential issuer (e.g. Google, Amazon, Facebook, etc.).
        ///   - name: The name/label of the account, typically a username or email address
        ///   - digits: Number of digits to display for generated ``Code``s
        ///   - requiresTouch: Set to true if the credential should require touch to be used.
        public init(
            type: CredentialType,
            algorithm: HashAlgorithm,
            secret: Data,
            issuer: String?,
            name: String,
            digits: UInt8 = 6,
            requiresTouch: Bool = false
        ) {
            self.type = type
            self.algorithm = algorithm

            if secret.count < Self.minSecretLenght {
                var mutableSecret = secret
                mutableSecret.append(Data(count: Self.minSecretLenght - secret.count))
                self.secret = mutableSecret
            } else if algorithm == .SHA1 && secret.count > CC_SHA1_BLOCK_BYTES {
                self.secret = secret.sha1()
            } else if algorithm == .SHA256 && secret.count > CC_SHA256_BLOCK_BYTES {
                self.secret = secret.sha256()
            } else if algorithm == .SHA512 && secret.count > CC_SHA512_BLOCK_BYTES {
                self.secret = secret.sha512()
            } else {
                self.secret = secret
            }

            self.issuer = issuer
            self.name = name
            self.digits = digits
            self.requiresTouch = requiresTouch
        }
    }
}

extension OATHSession.HashAlgorithm {
    internal init?(fromUrl url: URL) throws {
        if let name = url.queryValueFor(key: "algorithm") {
            switch name {
            case "SHA1":
                self = .SHA1
            case "SHA256":
                self = .SHA256
            case "SHA512":
                self = .SHA512
            default:
                throw OATHSession.CredentialTemplateError.parseAlgorithm
            }
        } else {
            return nil
        }
    }
}

extension OATHSession.CredentialType {
    internal init(fromURL url: URL) throws {
        let type = url.host?.lowercased()

        switch type {
        case "totp":
            if let stringPeriod = url.queryValueFor(key: "period"), let period = Double(stringPeriod) {
                self = .TOTP(period: period)
            } else {
                self = .TOTP()
            }
        case "hotp":
            if let stringCounter = url.queryValueFor(key: "counter"), let counter = UInt32(stringCounter) {
                self = .HOTP(counter: counter)
            } else {
                self = .HOTP()
            }
        default:
            throw OATHSession.CredentialTemplateError.parseType
        }
    }
}

extension URL {
    internal func queryValueFor(key: String) -> String? {
        let components = URLComponents(url: self, resolvingAgainstBaseURL: true)
        return components?.queryItems?.first(where: { $0.name == key })?.value
    }
}
