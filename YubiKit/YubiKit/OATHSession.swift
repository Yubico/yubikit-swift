//
//  OATHSession.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation
import CryptoKit
import CryptoTokenKit

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

extension TKTLVRecord {
    static func dictionaryOfData(from data: Data) -> [TKTLVTag: Data]? {
        self.sequenceOfRecords(from: data)?.reduce(into: [TKTLVTag: Data]()) {
            $0[$1.tag] = $1.value
        }
    }
}

let tagVersion: TKTLVTag = 0x79
let tagName: TKTLVTag = 0x71
let tagChallenge: TKTLVTag = 0x74
let typeHOTP: TKTLVTag = 0x77
let typeTouch: TKTLVTag = 0x7c

let defaultPeriod = 30.0

public final class OATHSession: Session, InternalSession {
    
    
    public enum AccountType: UInt8 {
        case HOTP = 0x10
        case TOTP = 0x20
    }
    
    public enum HashAlgorithm: UInt8 {
        case SHA1   = 0x01
        case SHA256 = 0x02
        case SHA512 = 0x03
    }
    
    
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?
    
    private let salt: Data
    private let challenge: Data?
    private let version: Version
    private let deviceId: String
    
    private init(connection: Connection) async throws {
        let data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
        let selectOathApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, data: data, type: .short)
        let resultData = try await connection.send(apdu: selectOathApdu)
        guard let result = TKBERTLVRecord.dictionaryOfData(from: resultData) else { throw "OATH response data not TLV formatted" }
        
        challenge = result[tagChallenge]

        guard let versionData = result[tagVersion],
              let version = Version(withData: versionData) else { throw "Missing version information in OATH response" }
        self.version = version
        
        guard let salt = result[tagName] else { throw "Missing salt in OATH response" }
        self.salt = salt
        
        let digest = SHA256.hash(data: salt)
        guard digest.data.count >= 16 else { throw "Failed deriving device id. To little data." }
        deviceId = digest.data.subdata(in: 0..<16).base64EncodedString().replacingOccurrences(of: "=", with: "")
        
        self.connection = connection
        var internalConnection = self.internalConnection
        internalConnection.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> OATHSession {
        // Close active session if there is one
        let internalConnection = connection as! InternalConnection
        await internalConnection.session?.end(withConnectionStatus: .leaveOpen)
        // Create a new OATHSession
        let session = try await OATHSession(connection: connection)
        return session
    }
    
    public func end(withConnectionStatus status: ConnectionStatus = .leaveOpen) async {
        switch status {
        case .close(let result):
            endingResult = result
            await connection?.close(result: result)
        default: break
        }
        sessionEnded = true
        var internalConnection = self.internalConnection
        internalConnection.session = nil
        connection = nil
        if case .leaveOpen = status {
            print("End OATHSesssion and close connection")
        } else {
            print("End OATHSesssion")
        }
    }
    
    public func sessionDidEnd() async throws -> Error? {
        print("await OATH sessionDidEnd")
//        _ = try await connection?.send(apdu: APDU())
        print("OATH session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }
    
    public func listAccounts() async throws -> [Account] {
        guard let connection else { throw "No connection to YubiKey" }
        let apdu = APDU(cla: 0, ins: 0xa1, p1: 0, p2: 0, data: nil, type: .short)
        let resultData = try await connection.send(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: resultData) else { throw "OATH response data not TLV formatted" }
        return try result.map {
            guard $0.tag == 0x72 else { throw "Unexpected tag" }
            let bytes = $0.value.bytes
            let accountType = AccountType(rawValue: bytes[0] & 0xf0)!
            let hashAlgorithm = HashAlgorithm(rawValue: bytes[0] & 0x0f)!
            guard let accountId = AccountId(data: $0.value.dropFirst(), accountType: accountType) else { throw "Malformed account data" }
            return Account(deviceId: deviceId, id: $0.value.dropFirst(), type: accountType, hashAlgorithm: hashAlgorithm, period: accountId.period, name: accountId.account, issuer: accountId.issuer)
        }
    }
    
    public func calculateCode(account: Account, timestamp: Date = Date()) async throws -> Code {
        guard account.deviceId == self.deviceId else { throw "The given account belongs to a different YubiKey." }
        let challengeTLV: TKBERTLVRecord
        if account.type == .TOTP {
            let time = timestamp.timeIntervalSince1970
            guard let period = account.period else { throw "Missing period for TOTP account" }
            let challenge = UInt64(time / Double(period))
            let bigChallenge = CFSwapInt64HostToBig(challenge)
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        } else {
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: Data())
        }
        
        let nameTLV = TKBERTLVRecord(tag: tagName, value: account.id)
        let calculateApdu = APDU(cla: 0x00, ins: 0xa2, p1: 0, p2: 1, data: nameTLV.data + challengeTLV.data, type: .extended)
        guard let response = try await connection?.send(apdu: calculateApdu) else { throw "Unexpected return data." }
        guard let result = TKBERTLVRecord.init(from: response) else { throw "Failed parsing response data into tlv" }
        
        guard let digits = result.value.first else { throw "No code" }
        let code = UInt32(bigEndian: result.value.subdata(in: 1..<result.value.count).uint32)
        let stringCode = String(format: "%0\(digits)d", UInt(code))
        return Code(code: stringCode, timestamp: timestamp, period: account.period)
    }
    
    public func calculateCodes(timestamp: Date = Date()) async throws -> [(Account, Code?)] {
        print("Start OATH calculateCodes")
        let time = timestamp.timeIntervalSince1970
        let challenge = UInt64(time / 30)
        let bigChallenge = CFSwapInt64HostToBig(challenge)
        let challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        let calculateAllApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01, data: challengeTLV.data, type: .short)
        guard let connection else { throw "No connection to YubiKey" }
        let resultData = try await connection.send(apdu: calculateAllApdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: resultData)?.tuples() else { throw "Unexpected return data" }
        
        return try await result.asyncMap { (name, response) in
            guard name.tag == 0x71 else { throw "Unexpected tag" }
            
            let accountType = response.tag == typeHOTP ? AccountType.HOTP : AccountType.TOTP
            guard let accountId = AccountId(data: name.value, accountType: accountType) else { throw "Malformed account data" }
            let account = Account(deviceId: deviceId, id: name.value, type: accountType, period: accountId.period, name: accountId.account, issuer: accountId.issuer)
            
            if response.value.count == 5 {
                if account.period != defaultPeriod {
                    let code = try await calculateCode(account: account, timestamp: timestamp)
                    return (account, code)
                } else {
                    let digits = response.value.first!
                    let code = UInt32(bigEndian: response.value.subdata(in: 1..<response.value.count).uint32)
                    let stringCode = String(format: "%0\(digits)d", UInt(code))
                    return (account, Code(code: stringCode, timestamp: timestamp, period: account.period))
                }
            } else {
                return (account, nil)
            }
        }
    }
    
    deinit {
        print("deinit OATHSession")
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
                period = accountType == .TOTP ? defaultPeriod : nil
                issuer = String(match.issuer)
                account = String(match.account)
            } else if let match = id.firstMatch(of: periodAndAccount) {
                period = TimeInterval(String(match.period))
                issuer = nil
                account = String(match.account)
            } else {
                period = accountType == .TOTP ? defaultPeriod : nil
                issuer = nil
                account = id
            }
        }
    }
}

extension Data {
    var responseStatusCode: UInt16 {
        let data = self.subdata(in: self.count - 2..<self.count)
        return CFSwapInt16BigToHost(data.uint16)
    }
    
    var responseData: Data {
        return self.subdata(in: 0..<self.count - 2)
    }
    
    
}
