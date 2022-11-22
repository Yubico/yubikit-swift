//
//  OATHSession+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-11-21.
//

import Foundation

extension OATHSession {
    
    public enum AccountType: CustomStringConvertible {
        
        case HOTP(counter: Int)
        case TOTP(period: TimeInterval)
        
        static func isHOTP(_ code: UInt8) -> Bool {
            return code == 0x10
        }
        
        static func isTOTP(_ code: UInt8) -> Bool {
            return code == 0x20
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
    
    
}
