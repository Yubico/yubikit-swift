//
//  OATHSession+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-11-21.
//

import Foundation

extension OATHSession {
    
    public enum AccountType: UInt8 {
        case HOTP = 0x10
        case TOTP = 0x20
    }
    
    public enum HashAlgorithm: UInt8 {
        case SHA1   = 0x01
        case SHA256 = 0x02
        case SHA512 = 0x03
    }
    
    public struct Account: Identifiable, CustomStringConvertible, CustomDebugStringConvertible {

        public let deviceId: String
        public let id: Data
        public let type: OATHSession.AccountType
        public let hashAlgorithm: OATHSession.HashAlgorithm?
        public let period: TimeInterval?
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
            switch type {
            case .HOTP:
                return "Account(type: HOTP, label:\(label), algorithm: \(hashAlgorithm.debugDescription)"
            case .TOTP:
                return "Account(type: TOTP, label:\(label), period: \(period ?? -1), algorith: \(hashAlgorithm.debugDescription)"
            }
        }
        public var debugDescription: String {
            self.description
        }

        init(deviceId: String, id: Data, type: OATHSession.AccountType, hashAlgorithm: OATHSession.HashAlgorithm? = nil, period: TimeInterval?, name: String, issuer: String?) {
            self.deviceId = deviceId
            self.id = id
            self.type = type
            self.hashAlgorithm = hashAlgorithm
            self.period = period
            self.name = name
            self.issuer = issuer
        }
    }
    
    struct AccountId {
        
        let account: String
        let issuer: String?
        let period: TimeInterval?
        
        init?(data: Data, accountType: AccountType) {
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
                period = accountType == .TOTP ? oathDefaultPeriod : nil
                issuer = String(match.issuer)
                account = String(match.account)
            } else if let match = id.firstMatch(of: periodAndAccount) {
                period = TimeInterval(String(match.period))
                issuer = nil
                account = String(match.account)
            } else {
                period = accountType == .TOTP ? oathDefaultPeriod : nil
                issuer = nil
                account = id
            }
        }
    }

    public struct Code: Identifiable, CustomStringConvertible, CustomDebugStringConvertible {
        
        public var description: String {
            let dateFormatter = DateFormatter()
            dateFormatter.dateFormat = "HH:mm:ss"
            return "Code(\(code), validFrom:\(dateFormatter.string(from: validFrom)), validTo:\(dateFormatter.string(from: validTo))"
        }
        public var debugDescription: String {
            self.description
        }
        
        public let id = UUID()
        public let code: String
        public var validFrom: Date {
            guard let period else { return Date() }
            return Date(timeIntervalSince1970: timestamp.timeIntervalSince1970 - timestamp.timeIntervalSince1970.truncatingRemainder(dividingBy: period))
        }
        public var validTo: Date {
            guard let period else { return validFrom.addingTimeInterval(.infinity)}
            return validFrom.addingTimeInterval(period)
        }
        
        init(code: String, timestamp: Date, period: TimeInterval?) {
            self.code = code
            self.timestamp = timestamp
            self.period = period
        }
        
        private let timestamp: Date
        private let period: TimeInterval?

    }
    
    
}
