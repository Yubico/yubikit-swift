//
//  OATHSession.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation
import CryptoTokenKit

public struct Code: Identifiable {
    public let id = UUID()
    public let code: String
}


public struct Account: Identifiable {
    public let id: Data
    public let type: OATHSession.AccountType
    public let hashAlgorithm: OATHSession.HashAlgorithm
    public let period: Int?
    public let name: String
    public let issuer: String?
    public var label: String {
        if let issuer {
            return "\(issuer):\(name)"
        } else {
            return name
        }
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
let defaultPeriod = 30

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

    private let salt: Data?
    private let version: Version
    private let challenge: Data?

    private init(connection: Connection) async throws {
        self.connection = connection
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
            guard $0.tag == 0x72 else { throw "Wrong data" }
            let bytes = $0.value.bytes
            print($0.data.hexEncodedString)
            let accountType = AccountType(rawValue: bytes[0] & 0xf0)!
            let hashAlgorithm = HashAlgorithm(rawValue: bytes[0] & 0x0f)!
            guard let id = String(data: $0.data.dropFirst(), encoding: .utf8) else { throw "Not enough data" }
            
            let account: String
            let issuer: String?
            let period: Int?
            
            // "period/issuer:account"
            let periodIssuerAndAccount = /^(?<period>\d+)\/(?<issuer>.+):(?<account>.+)$/
            // "issuer:account"
            let issuerAndAccount = /^(?<issuer>.+):(?<account>.+)$/
            // "period/account"
            let periodAndAccount = /^(?<period>\d+)\/(?<account>.+)$/
            
            if let match = id.firstMatch(of: periodIssuerAndAccount) {
                period = Int(String(match.period))
                issuer = String(match.issuer)
                account = String(match.account)
            } else if let match = id.firstMatch(of: issuerAndAccount) {
                period = accountType == .TOTP ? defaultPeriod : nil
                issuer = String(match.issuer)
                account = String(match.account)
            } else if let match = id.firstMatch(of: periodAndAccount) {
                period = Int(String(match.period))
                issuer = nil
                account = String(match.account)
            } else {
                period = accountType == .TOTP ? defaultPeriod : nil
                issuer = nil
                account = id
            }

            return Account(id: $0.value.dropFirst(), type: accountType, hashAlgorithm: hashAlgorithm, period: period, name: account, issuer: issuer)
        }
    }
    
    public func calculateCode() async throws -> Code {
        print("Start OATH calculateCode()")
//        _ = try await connection?.send(apdu: APDU())
        print("Finished calculateCode()")
        return Code(code: "\(Int.random(in: 1000...9999))")
    }
    
    public func calculateCodes(timestamp: Date = Date()) async throws -> [Code] {
        print("Start OATH calculateCodes")
        // Not fully implemented yet. Returning fake codes.
        return (1...6).map { _ in Code(code: "\(Int.random(in: 1000...9999))") }
        
        let time = timestamp.timeIntervalSince1970
        let challenge = UInt64(time / 30)
        let bigChallenge = CFSwapInt64HostToBig(challenge)
        var data = Data()
        data.append(0x74)
        data.append(bigChallenge.data)
        let calculateAllApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01, data: data, type: .short)
        guard let connection = connection else { throw "No connection to YubiKey!" }
        let result = try await connection.send(apdu: calculateAllApdu)
        print(result.hexEncodedString)
        print(result.responseStatusCode)
        guard result.responseStatusCode == 0x9000 else {
            print("Status code error: \(result.responseStatusCode)")
            throw "APDU error: \(result.responseStatusCode)"
        }
        print(result.hexEncodedString)
        print(result.responseStatusCode)
        print(result.responseData.hexEncodedString)
        if result.responseStatusCode == 0x9000 {
            print("status code ok")
        }
        print("Finished OATH calculateCodes\n")
        return (1...6).map { _ in Code(code: "\(Int.random(in: 1000...9999))") }
        
    }
    
    public func calculateFailingCode() async throws -> String {
//        _ = try await connection?.send(apdu: APDU())
        throw "Something went wrong!"
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
