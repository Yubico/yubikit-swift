//
//  OATHSession+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-11-21.
//

import Foundation

private var hotpCode: UInt8 = 0x10
private var totpCode: UInt8 = 0x20

extension OATHSession {
    
    public enum AccountType: CustomStringConvertible {
        
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
        
        static func isHOTP(_ code: UInt8) -> Bool {
            return code == hotpCode
        }
        
        static func isTOTP(_ code: UInt8) -> Bool {
            return code == totpCode
        }
        
        public var description: String {
            switch self {
            case .HOTP(counter: let counter):
                return "HOTP(\(counter))"
            case .TOTP(period: let period):
                return "TOTP(\(period))"
            }
        }
    }
    
    public enum HashAlgorithm: UInt8 {
        case SHA1   = 0x01
        case SHA256 = 0x02
        case SHA512 = 0x03
    }
    
    public struct Account: Identifiable, CustomStringConvertible {

        public let deviceId: String
        public let id: Data
        public let type: OATHSession.AccountType
        public let hashAlgorithm: OATHSession.HashAlgorithm?
        public let name: String
        public let issuer: String?
        public var label: String {
            if let issuer {
                return "\(issuer):\(name)"
            } else {
                return name
            }
        }
        public var description: String {
            return "Account(type: \(type), label:\(label), algorithm: \(hashAlgorithm.debugDescription)"
        }

        init(deviceId: String, id: Data, type: OATHSession.AccountType, hashAlgorithm: OATHSession.HashAlgorithm? = nil, name: String, issuer: String?) {
            self.deviceId = deviceId
            self.id = id
            self.type = type
            self.hashAlgorithm = hashAlgorithm
            self.name = name
            self.issuer = issuer
        }
    }
    
    struct AccountIdParser {
        
        let account: String
        let issuer: String?
        let period: TimeInterval?
        
        init?(data: Data) {
            // "period/issuer:account"
            let periodIssuerAndAccount = /^(?<period>\d+)\/(?<issuer>.+):(?<account>.+)$/
            // "issuer:account"
            let issuerAndAccount = /^(?<issuer>.+):(?<account>.+)$/
            // "period/account"
            let periodAndAccount = /^(?<period>\d+)\/(?<account>.+)$/
            
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

    public struct Code: Identifiable, CustomStringConvertible {
        
        public var description: String {
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "HH:mm:ss"
            return "Code(\(code), validFrom:\(dateFormatter.string(from: validFrom)), validTo:\(dateFormatter.string(from: validTo))"
        }
        
        public let id = UUID()
        public let code: String
        public var validFrom: Date {
            switch accountType {
            case .HOTP(_):
                return Date()
            case .TOTP(period: let period):
                return Date(timeIntervalSince1970: timestamp.timeIntervalSince1970 - timestamp.timeIntervalSince1970.truncatingRemainder(dividingBy: period))
            }
        }
        public var validTo: Date {
            switch accountType {
            case .HOTP(_):
                return validFrom.addingTimeInterval(.infinity)
            case .TOTP(period: let period):
                return validFrom.addingTimeInterval(period)
            }
        }
        
        init(code: String, timestamp: Date, accountType: AccountType) {
            self.code = code
            self.timestamp = timestamp
            self.accountType = accountType
        }
        
        private let timestamp: Date
        private let accountType: AccountType

    }
    
    
    public struct AccountTemplate {
        
        private let minSecretLenght = 14
        
        public var key: String {
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
        
        public init(type: AccountType, algorithm: HashAlgorithm, secret: Data, issuer: String?, name: String, digits: UInt8, requiresTouch: Bool = false) {
            self.type = type
            self.algorithm = algorithm
            if secret.count < minSecretLenght {
                var mutableSecret = secret
                mutableSecret.append(Data(count: minSecretLenght - secret.count))
                self.secret = mutableSecret
            } else {
                self.secret = secret
            }
            self.issuer = issuer
            self.name = name
            self.digits = digits
            self.requiresTouch = requiresTouch
        }
        
        let type: AccountType
        let algorithm: HashAlgorithm
        let secret: Data
        let issuer: String?
        let name: String
        let digits: UInt8
        let requiresTouch: Bool
    }
    
}
