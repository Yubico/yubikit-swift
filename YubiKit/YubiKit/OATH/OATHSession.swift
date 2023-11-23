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

import Foundation
import CryptoKit
import CryptoTokenKit
import CommonCrypto

fileprivate let tagVersion: TKTLVTag = 0x79
fileprivate let tagName: TKTLVTag = 0x71
fileprivate let tagChallenge: TKTLVTag = 0x74
fileprivate let tagTypeHOTP: TKTLVTag = 0x77
fileprivate let tagTypeTouch: TKTLVTag = 0x7c
fileprivate let tagSetCodeKey: TKTLVTag = 0x73
fileprivate let tagSetCodeResponse: TKTLVTag = 0x75

let oathDefaultPeriod = 30.0

public enum OATHSessionError: Error {
    case wrongPassword
    case responseDataNotTLVFormatted
    case missingVersionInfo
    case missingSalt
    case failedDerivingDeviceId
    case unexpectedTag
    case unexpectedData
    case credentialNotPresentOnCurrentYubiKey
}

/// An interface to the OATH application on the YubiKey.
///
/// The OATHSession is an interface to the OATH appcliation on the YubiKey that will
/// let you store, calculate and edit TOTP and HOTP credentials on the YubiKey. Learn
/// more about OATH on the [Yubico developer website](https://developers.yubico.com/OATH/).
public final class OATHSession: Session, InternalSession {
    func connection() async -> Connection? {
        return _connection
    }
    
    func setConnection(_ connection: Connection?) async {
        _connection = connection
    }
    
    
    internal weak var _connection: Connection?
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
        print("⚡️ init OATHSession")
        self.selectResponse = try await Self.selectApplication(withConnection: connection)
        await self.setConnection(connection)
        let internalConnection = await internalConnection()
        await internalConnection?.setSession(self)
    }
    
    private static func selectApplication(withConnection connection: Connection) async throws -> SelectResponse {
        let data: Data = try await connection.selectApplication(application: .oath)
        guard let result = TKBERTLVRecord.dictionaryOfData(from: data) else { throw OATHSessionError.responseDataNotTLVFormatted }

        let challenge = result[tagChallenge]
        
        guard let versionData = result[tagVersion],
              let version = Version(withData: versionData) else { throw OATHSessionError.missingVersionInfo }
        
        guard let salt = result[tagName] else { throw OATHSessionError.missingSalt }
        
        let digest = SHA256.hash(data: salt)
        guard digest.data.count >= 16 else { throw OATHSessionError.failedDerivingDeviceId }
        let deviceId = digest.data.subdata(in: 0..<16).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return SelectResponse(salt: salt, challenge: challenge, version: version, deviceId: deviceId)
    }
    
    public static func session(withConnection connection: Connection) async throws -> OATHSession {
        // Close active session if there is one
        let internalConnection = connection as! InternalConnection
        let currentSession = await internalConnection.session()
        await currentSession?.end()
        // Create a new OATHSession
        let session = try await OATHSession(connection: connection)
        return session
    }
    
    public func end() async {
        let internalConnection = _connection as? InternalConnection
        await internalConnection?.setSession(nil)
        self._connection = nil
    }
    
    public func sessionDidEnd() async -> Error? {
        print("await OATH sessionDidEnd")
//        _ = try await connection?.send(apdu: APDU())
        print("OATH session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }
    
    public func reset() async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        print("Reset OATH application")
        let apdu = APDU(cla: 0, ins: 0x04, p1: 0xde, p2: 0xad)
        let _ = try await connection.send(apdu: apdu)
        selectResponse = try await Self.selectApplication(withConnection: connection)
    }
    
    /// Adds a new Credential to the YubiKey.
    ///
    /// The Credential ID (see ``OATHSession/CredentialTemplate/identifier``) must be unique to the YubiKey, or the
    /// existing Credential with the same ID will be overwritten.
    ///
    /// Setting requireTouch requires support for FEATURE_TOUCH, available on YubiKey 4.2 or later.
    /// Using SHA-512 requires support for FEATURE_SHA512, available on YubiKey 4.3.1 or later.
    /// - Parameter template: The template describing the credential.
    /// - Returns: The newly added credential.
    @discardableResult public func addCredential(template: CredentialTemplate) async throws -> Credential {
        guard let connection = _connection else { throw SessionError.noConnection }
        guard let nameData = template.identifier.data(using: .utf8) else { throw OATHSessionError.unexpectedData }
        let nameTlv = TKBERTLVRecord(tag: 0x71, value: nameData)
        var keyData = Data()
        
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
        
        let apdu = APDU(cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00, command: data)
        let _ = try await connection.send(apdu: apdu)
        return Credential(deviceId: selectResponse.deviceId, id: nameData, type: template.type, name: template.name, issuer: template.issuer)
    }
    
    /// Deletes an existing Credential from the YubiKey.
    /// - Parameter credential: The credential that will be deleted from the YubiKey.
    public func deleteCredential(_ credential: Credential) async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        let deleteTlv = TKBERTLVRecord(tag: 0x71, value: credential.id)
        let apdu = APDU(cla: 0, ins: 0x02, p1: 0, p2: 0, command: deleteTlv.data)
        let _ = try await connection.send(apdu: apdu)
    }
    
    /// List credentials on YubiKey.
    /// - Returns: An array of Credentials.
    public func listCredentials() async throws -> [Credential] {
        guard let connection = _connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: 0xa1, p1: 0, p2: 0)
        let data = try await connection.send(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: data) else { throw OATHSessionError.responseDataNotTLVFormatted }
        return try result.map {
            guard $0.tag == 0x72 else { throw OATHSessionError.unexpectedTag }
            guard let credentialId = CredentialIdParser(data: $0.value.dropFirst()) else { throw OATHSessionError.unexpectedData }
            let bytes = $0.value.bytes
            let typeCode = bytes[0] & 0xf0
            let credentialType: CredentialType
            if CredentialType.isTOTP(typeCode) {
                credentialType = .TOTP(period: credentialId.period ?? oathDefaultPeriod)
            } else if CredentialType.isHOTP(typeCode) {
                credentialType = .HOTP(counter: 0)
            } else {
                throw OATHSessionError.unexpectedData
            }
            
            guard let hashAlgorithm = HashAlgorithm(rawValue: bytes[0] & 0x0f) else { throw OATHSessionError.unexpectedData }

            return Credential(deviceId: selectResponse.deviceId, id: $0.value.dropFirst(), type: credentialType, hashAlgorithm: hashAlgorithm, name: credentialId.account, issuer: credentialId.issuer)
        }
    }
    
    /// Returns a new Code for a stored Credential.
    /// - Parameters:
    ///   - credential: The stored Credential to calculate a new code for.
    ///   - timestamp: The timestamp which is used as start point for TOTP, this is ignored for HOTP.
    /// - Returns: Calculated code.
    public func calculateCode(credential: Credential, timestamp: Date = Date()) async throws -> Code {
        guard let connection = _connection else { throw SessionError.noConnection }

        guard credential.deviceId == self.selectResponse.deviceId else { throw OATHSessionError.credentialNotPresentOnCurrentYubiKey }
        let challengeTLV: TKBERTLVRecord
        
        switch credential.type {
        case .HOTP(counter: let counter):
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: Data())
        case .TOTP(period: let period):
            let time = timestamp.timeIntervalSince1970
            let challenge = UInt64(time / Double(period))
            let bigChallenge = CFSwapInt64HostToBig(challenge)
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        }
        
        let nameTLV = TKBERTLVRecord(tag: tagName, value: credential.id)
        let apdu = APDU(cla: 0x00, ins: 0xa2, p1: 0, p2: 1, command: nameTLV.data + challengeTLV.data, type: .extended)
        
        let data = try await connection.send(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: data) else { throw OATHSessionError.responseDataNotTLVFormatted }
        
        guard let digits = result.value.first else { throw OATHSessionError.unexpectedData }
        let code = UInt32(bigEndian: result.value.subdata(in: 1..<result.value.count).uint32)
        let stringCode = String(format: "%0\(digits)d", UInt(code))
        return Code(code: stringCode, timestamp: timestamp, credentialType: credential.type)
    }
    
    /// List all credentials on the YubiKey and calculate each credentials code.
    ///
    /// Credentials which use HOTP, or which require touch, will not be calculated.
    /// They will still be present in the result, but with a nil value.
    /// - Parameter timestamp: The timestamp which is used as start point for TOTP, this is ignored for HOTP.
    /// - Returns: An array of tuples containing a ``Credential`` and an optional ``Code``.
    public func calculateCodes(timestamp: Date = Date()) async throws -> [(Credential, Code?)] {
        print("Start OATH calculateCodes")
        let time = timestamp.timeIntervalSince1970
        let challenge = UInt64(time / 30)
        let bigChallenge = CFSwapInt64HostToBig(challenge)
        let challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        let apdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01, command: challengeTLV.data)
        guard let connection = _connection else { throw SessionError.noConnection }
        let data = try await connection.send(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: data)?.tuples() else { throw OATHSessionError.responseDataNotTLVFormatted }
        
        return try await result.asyncMap { (name, response) in
            guard name.tag == 0x71 else { throw OATHSessionError.unexpectedTag }

            guard let credentialId = CredentialIdParser(data: name.value) else { throw OATHSessionError.unexpectedData }

            let credentialType: CredentialType
            if response.tag == tagTypeHOTP {
                credentialType = .HOTP(counter: 0)
            } else {
                credentialType = .TOTP(period: credentialId.period ?? oathDefaultPeriod)
            }
            
            let credential = Credential(deviceId: self.selectResponse.deviceId, id: name.value, type: credentialType, name: credentialId.account, issuer: credentialId.issuer)
            
            if response.value.count == 5 {
                if credentialId.period != oathDefaultPeriod {
                    let code = try await self.calculateCode(credential: credential, timestamp: timestamp)
                    return (credential, code)
                } else {
                    let digits = response.value.first!
                    let code = UInt32(bigEndian: response.value.subdata(in: 1..<response.value.count).uint32)
                    let stringCode = String(format: "%0\(digits)d", UInt(code))
                    return (credential, Code(code: stringCode, timestamp: timestamp, credentialType: credentialType))
                }
            } else {
                return (credential, nil)
            }
        }
    }
    
    /// Sets an Access Key derived from a password. Once a key is set, any usage of the credentials stored will
    /// require the application to be unlocked via one of the unlock functions. Also see ``setAccessKey(_:)``.
    /// - Parameter password: The user-supplied password to set.
    public func setPassword(_ password: String) async throws {
        let derivedKey = try deriveAccessKey(from: password)
        try await self.setAccessKey(derivedKey)
    }
    
    /// Unlock with password.
    /// - Parameter password: The user-supplied password used to unlock the application.
    public func unlockWithPassword(_ password: String) async throws {
        let derivedKey = try deriveAccessKey(from: password)
        try await self.unlockWithAccessKey(derivedKey)
    }
    

    /// Sets an access key.
    ///
    /// Once an access key is set, any usage of the credentials stored will require the application
    /// to be unlocked via one of the unlock methods, which requires knowledge of the access key.
    /// Typically this key is derived from a password (see ``deriveAccessKey(from:)``). This method
    /// sets the raw 16 byte key.
    /// - Parameter accessKey: The shared secret key used to unlock access to the application.
    public func setAccessKey(_ accessKey: Data) async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        let header = CredentialType.TOTP().code | HashAlgorithm.SHA1.rawValue
        var data = Data([header])
        data.append(accessKey)
        let keyTlv = TKBERTLVRecord(tag: tagSetCodeKey, value: data)
        
        // Challenge
        let challenge = Data.random(length: 8)
        let challengeTlv = TKBERTLVRecord(tag: tagChallenge, value: challenge)
        
        // Response
        let response = challenge.hmacSha1(usingKey: accessKey)
        let responseTlv = TKBERTLVRecord(tag: tagSetCodeResponse, value: response)
        let apdu = APDU(cla: 0, ins: 0x03, p1: 0, p2: 0, command: keyTlv.data + challengeTlv.data + responseTlv.data)
        let _ = try await connection.send(apdu: apdu)
    }
    
    /// Unlock OATH application on the YubiKey. Once unlocked other commands may be sent to the key.
    ///
    /// Once unlocked, the application will remain unlocked for the duration of the session.
    /// See the [YKOATH protocol specification](https://developers.yubico.com/OATH/) for further details.
    /// - Parameter accessKey: The shared access key.
    public func unlockWithAccessKey(_ accessKey: Data) async throws {
        guard let connection = _connection, let responseChallenge = self.selectResponse.challenge else { throw SessionError.noConnection }
        let reponseTlv = TKBERTLVRecord(tag: tagSetCodeResponse, value: responseChallenge.hmacSha1(usingKey: accessKey))
        let challenge = Data.random(length: 8)
        let challengeTlv = TKBERTLVRecord(tag: tagChallenge, value: challenge)
        let apdu = APDU(cla: 0, ins: 0xa3, p1: 0, p2: 0, command: reponseTlv.data + challengeTlv.data)

        do {
            let data = try await connection.send(apdu: apdu)
            guard let resultTlv = TKBERTLVRecord(from: data), resultTlv.tag == tagSetCodeResponse else {
                throw OATHSessionError.unexpectedTag
            }
            let expectedResult = challenge.hmacSha1(usingKey: accessKey)
            guard resultTlv.value == expectedResult else { throw OATHSessionError.unexpectedData }
        } catch {
            if let reponseError = error as? ResponseError, reponseError.statusCode == .wrongData {
                throw OATHSessionError.wrongPassword
            } else {
                throw error
            }
        }
    }
    
    deinit {
        print("deinit OATHSession")
    }
}

struct DeriveAccessKeyError: Error {
    let cryptorStatus: CCCryptorStatus
}

extension OATHSession {
    
    /// Derives an access key from a password and the device-specific salt. The key is derived by running
    /// 1000 rounds of PBKDF2 using the password and salt as inputs, with a 16 byte output.
    /// - Parameter password: A user-supplied password.
    /// - Returns: Access key for unlocking the session.
    public func deriveAccessKey(from password: String) throws -> Data {
        var derivedKey = Data(count: 16)
        try derivedKey.withUnsafeMutableBytes { (outputBytes: UnsafeMutableRawBufferPointer) in
            let status = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                              password,
                                              password.utf8.count,
                                              self.selectResponse.salt.bytes,
                                              self.selectResponse.salt.bytes.count,
                                              CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                                              1000,
                                              outputBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                      kCCKeySizeAES256)
            guard status == kCCSuccess else {
                throw DeriveAccessKeyError(cryptorStatus: status)
            }
        }
        return derivedKey
    }
}

extension Data {
    internal func hmacSha1(usingKey key: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), key.bytes, key.bytes.count, self.bytes, self.bytes.count, &digest)
        return Data(digest)
    }
}
