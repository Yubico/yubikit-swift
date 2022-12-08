//
//  OATHSession.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation
import CryptoKit
import CryptoTokenKit

fileprivate let tagVersion: TKTLVTag = 0x79
fileprivate let tagName: TKTLVTag = 0x71
fileprivate let tagChallenge: TKTLVTag = 0x74
fileprivate let typeHOTP: TKTLVTag = 0x77
fileprivate let typeTouch: TKTLVTag = 0x7c

let oathDefaultPeriod = 30.0

public final class OATHSession: Session, InternalSession {
    
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?
    
    private struct SelectResponse {
        let salt: Data
        let challenge: Data?
        let version: Version
        let deviceId: String
    }
    
    private var selectResponse: SelectResponse
    
    private init(connection: Connection) async throws {
        selectResponse = try await Self.selectApplication(withConnection: connection)
        self.connection = connection
        var internalConnection = self.internalConnection
        internalConnection.session = self
    }
    
    private static func selectApplication(withConnection connection: Connection) async throws -> SelectResponse {
        let data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
        let selectOathApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, data: data, type: .short)
        let resultData = try await connection.send(apdu: selectOathApdu)
        guard let result = TKBERTLVRecord.dictionaryOfData(from: resultData.data) else { throw "OATH response data not TLV formatted" }
        
        let challenge = result[tagChallenge]
        
        guard let versionData = result[tagVersion],
              let version = Version(withData: versionData) else { throw "Missing version information in OATH response" }
        
        guard let salt = result[tagName] else { throw "Missing salt in OATH response" }
        
        let digest = SHA256.hash(data: salt)
        guard digest.data.count >= 16 else { throw "Failed deriving device id. To little data." }
        let deviceId = digest.data.subdata(in: 0..<16).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return SelectResponse(salt: salt, challenge: challenge, version: version, deviceId: deviceId)
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
    
    public func reset() async throws {
        guard let connection else { throw "No connection to YubiKey" }
        print("Reset OATH application")
        let apdu = APDU(cla: 0, ins: 0x04, p1: 0xde, p2: 0xad, data: nil, type: .short)
        _ = try await connection.send(apdu: apdu)
        selectResponse = try await Self.selectApplication(withConnection: connection)
    }
    
    @discardableResult public func addAccount(template: AccountTemplate) async throws -> Account? {
        guard let connection else { throw "No connection to YubiKey" }
        // name
        print(template.key)
        guard let nameData = template.key.data(using: .utf8) else { throw "Failed encode account key" }
        let nameTlv = TKBERTLVRecord(tag: 0x71, value: nameData)
        // key
        var keyData = Data()
        
//        keyData.append(UInt8(template.type.code | template.algorithm.rawValue).data)
        keyData.append(template.type.code | template.algorithm.rawValue)
        keyData.append(template.digits.data)
        keyData.append(template.secret)
        let keyTlv = TKBERTLVRecord(tag: 0x73, value: keyData)
        
        var data =  [nameTlv, keyTlv].recordsAsData()
        if template.requiresTouch {
            data.append(UInt8(0x78))
            data.append(UInt8(0x02))
        }
        
        if case let .HOTP(counter) = template.type {
            data.append(TKBERTLVRecord(tag: 0x7a, value: counter.data).data)
        }
        
        let apdu = APDU(cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00, data: data, type: .short)
        let resultData = try await connection.send(apdu: apdu)
        return nil
    }
    
    public func listAccounts() async throws -> [Account] {
        guard let connection else { throw "No connection to YubiKey" }
        let apdu = APDU(cla: 0, ins: 0xa1, p1: 0, p2: 0, data: nil, type: .short)
        let response = try await connection.send(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: response.data) else { throw "OATH response data not TLV formatted" }
        return try result.map {
            guard $0.tag == 0x72 else { throw "Unexpected tag" }
            guard let accountId = AccountIdParser(data: $0.value.dropFirst()) else { throw "Malformed account data" }
            let bytes = $0.value.bytes
            let typeCode = bytes[0] & 0xf0
            let accountType: AccountType
            if AccountType.isTOTP(typeCode) {
                accountType = .TOTP(period: accountId.period ?? oathDefaultPeriod)
            } else if AccountType.isHOTP(typeCode) {
                accountType = .HOTP(counter: 0)
            } else {
                throw "Missing accoutn type code"
            }
            
            guard let hashAlgorithm = HashAlgorithm(rawValue: bytes[0] & 0x0f) else { throw "Mising hash algorithm" }

            return Account(deviceId: selectResponse.deviceId, id: $0.value.dropFirst(), type: accountType, hashAlgorithm: hashAlgorithm, name: accountId.account, issuer: accountId.issuer)
        }
    }
    
    public func calculateCode(account: Account, timestamp: Date = Date()) async throws -> Code {
        guard account.deviceId == self.selectResponse.deviceId else { throw "The given account belongs to a different YubiKey." }
        let challengeTLV: TKBERTLVRecord
        
        switch account.type {
        case .HOTP(counter: let counter):
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: Data())
        case .TOTP(period: let period):
            let time = timestamp.timeIntervalSince1970
            let challenge = UInt64(time / Double(period))
            let bigChallenge = CFSwapInt64HostToBig(challenge)
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        }
        
        let nameTLV = TKBERTLVRecord(tag: tagName, value: account.id)
        let calculateApdu = APDU(cla: 0x00, ins: 0xa2, p1: 0, p2: 1, data: nameTLV.data + challengeTLV.data, type: .extended)
        guard let response = try await connection?.send(apdu: calculateApdu) else { throw "Unexpected return data." }
        guard let result = TKBERTLVRecord.init(from: response.data) else { throw "Failed parsing response data into tlv" }
        
        guard let digits = result.value.first else { throw "No code" }
        let code = UInt32(bigEndian: result.value.subdata(in: 1..<result.value.count).uint32)
        let stringCode = String(format: "%0\(digits)d", UInt(code))
        return Code(code: stringCode, timestamp: timestamp, accountType: account.type)
    }
    
    public func calculateCodes(timestamp: Date = Date()) async throws -> [(Account, Code?)] {
        print("Start OATH calculateCodes")
        let time = timestamp.timeIntervalSince1970
        let challenge = UInt64(time / 30)
        let bigChallenge = CFSwapInt64HostToBig(challenge)
        let challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        let calculateAllApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01, data: challengeTLV.data, type: .short)
        guard let connection else { throw "No connection to YubiKey" }
        let response = try await connection.send(apdu: calculateAllApdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: response.data)?.tuples() else { throw "Unexpected return data" }
        
        return try await result.asyncMap { (name, response) in
            guard name.tag == 0x71 else { throw "Unexpected tag" }

            guard let accountId = AccountIdParser(data: name.value) else { throw "Malformed account data" }

            let accountType: AccountType
            if response.tag == typeHOTP {
                accountType = .HOTP(counter: 0)
            } else {
                accountType = .TOTP(period: accountId.period ?? oathDefaultPeriod)
            }
            
            let account = Account(deviceId: self.selectResponse.deviceId, id: name.value, type: accountType, name: accountId.account, issuer: accountId.issuer)
            
            if response.value.count == 5 {
                if accountId.period != oathDefaultPeriod {
                    let code = try await self.calculateCode(account: account, timestamp: timestamp)
                    return (account, code)
                } else {
                    let digits = response.value.first!
                    let code = UInt32(bigEndian: response.value.subdata(in: 1..<response.value.count).uint32)
                    let stringCode = String(format: "%0\(digits)d", UInt(code))
                    return (account, Code(code: stringCode, timestamp: timestamp, accountType: accountType))
                }
            } else {
                return (account, nil)
            }
        }
    }
    
    deinit {
        print("deinit OATHSession")
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
