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
import CryptoKit
import CryptoTokenKit
import Foundation
import OSLog

private let tagVersion: TKTLVTag = 0x79
private let tagName: TKTLVTag = 0x71
private let tagChallenge: TKTLVTag = 0x74
private let tagTypeHOTP: TKTLVTag = 0x77
private let tagTypeTouch: TKTLVTag = 0x7c
private let tagSetCodeKey: TKTLVTag = 0x73
private let tagResponse: TKTLVTag = 0x75

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
    case badCalculation
}

/// An interface to the OATH application on the YubiKey.
///
/// The OATHSession is an interface to the OATH appcliation on the YubiKey that will
/// let you store, calculate and edit TOTP and HOTP credentials on the YubiKey. Learn
/// more about OATH on the [Yubico developer website](https://developers.yubico.com/OATH/).
public final actor OATHSession: Session {

    private let connection: Connection
    private let processor: SCPProcessor?

    private struct SelectResponse {
        let salt: Data
        let challenge: Data?
        let version: Version
        let deviceId: String
    }

    private let selectResponse: SelectResponse
    public nonisolated var version: Version {
        selectResponse.version
    }

    // true means that the OATH session is locked
    public nonisolated var isAccessKeySet: Bool {
        selectResponse.challenge != nil && !selectResponse.challenge!.isEmpty
    }

    private init(connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws {
        self.selectResponse = try await Self.selectApplication(withConnection: connection)
        if let scpKeyParams {
            processor = try await SCPProcessor(connection: connection, keyParams: scpKeyParams, insSendRemaining: 0xa5)
        } else {
            processor = nil
        }
        self.connection = connection
    }

    private static func selectApplication(withConnection connection: Connection) async throws -> SelectResponse {
        let data: Data = try await connection.selectApplication(.oath)
        guard let result = TKBERTLVRecord.dictionaryOfData(from: data) else {
            throw OATHSessionError.responseDataNotTLVFormatted
        }

        let challenge = result[tagChallenge]

        guard let versionData = result[tagVersion],
            let version = Version(withData: versionData)
        else { throw OATHSessionError.missingVersionInfo }

        guard let salt = result[tagName] else { throw OATHSessionError.missingSalt }

        let digest = SHA256.hash(data: salt)
        guard digest.data.count >= 16 else { throw OATHSessionError.failedDerivingDeviceId }
        let deviceId = digest.data.subdata(in: 0..<16).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return SelectResponse(salt: salt, challenge: challenge, version: version, deviceId: deviceId)
    }

    public static func session(
        withConnection connection: Connection,
        scpKeyParams: SCPKeyParams? = nil
    ) async throws -> OATHSession {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(String(describing: connection))")
        // Create a new OATHSession
        let session = try await OATHSession(connection: connection, scpKeyParams: scpKeyParams)
        return session
    }

    public func reset() async throws {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)")
        let apdu = APDU(cla: 0, ins: 0x04, p1: 0xde, p2: 0xad)
        try await send(apdu: apdu)
    }

    nonisolated public func supports(_ feature: SessionFeature) -> Bool {
        feature.isSupported(by: version)
    }

    /// Adds a new Credential to the YubiKey.
    ///
    /// The Credential ID (see ``OATHSession/CredentialTemplate/identifier``) must be unique to the YubiKey, or the
    /// existing Credential with the same ID will be overwritten.
    ///
    /// Setting requireTouch requires support for touch, available on YubiKey 4.2 or later.
    /// Using SHA-512 requires support for SHA-512, available on YubiKey 4.3.1 or later.
    /// - Parameter template: The template describing the credential.
    /// - Returns: The newly added credential.
    @discardableResult
    public func addCredential(template: CredentialTemplate) async throws -> Credential {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)")
        if template.algorithm == .SHA512 {
            guard self.supports(OATHSessionFeature.sha512) else { throw SessionError.notSupported }
        }
        if template.requiresTouch {
            guard self.supports(OATHSessionFeature.touch) else { throw SessionError.notSupported }
        }
        guard let nameData = template.identifier.data(using: .utf8) else { throw OATHSessionError.unexpectedData }
        let nameTlv = TKBERTLVRecord(tag: 0x71, value: nameData)
        var keyData = Data()

        keyData.append(template.type.code | template.algorithm.rawValue)
        keyData.append(template.digits.data)
        keyData.append(template.secret)
        let keyTlv = TKBERTLVRecord(tag: 0x73, value: keyData)

        var data = [nameTlv, keyTlv].recordsAsData()
        if template.requiresTouch {
            data.append(UInt8(0x78))
            data.append(UInt8(0x02))
        }

        if case let .HOTP(counter) = template.type {
            data.append(TKBERTLVRecord(tag: 0x7a, value: counter.data).data)
        }

        let apdu = APDU(cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00, command: data)
        try await send(apdu: apdu)
        return Credential(
            deviceId: selectResponse.deviceId,
            id: nameData,
            type: template.type,
            name: template.name,
            issuer: template.issuer,
            requiresTouch: template.requiresTouch
        )
    }

    /// Sends to the key an OATH Rename request to update issuer and account on an existing credential.
    ///
    /// >Note: This functionality requires support for renaming, available on YubiKey 5.3 or later.
    ///
    /// - Parameters:
    ///   - credential: The credential to rename.
    ///   - newName: The new account name.
    ///   - newIssuer: The new issuer.
    public func renameCredential(_ credential: Credential, newName: String, newIssuer: String?) async throws {
        guard self.supports(OATHSessionFeature.rename) else { throw SessionError.notSupported }
        guard
            let currentId = CredentialIdentifier.identifier(
                name: credential.name,
                issuer: credential.issuer,
                type: credential.type
            ).data(using: .utf8),
            let renamedId = CredentialIdentifier.identifier(name: newName, issuer: newIssuer, type: credential.type)
                .data(using: .utf8)
        else { throw OATHSessionError.unexpectedData }
        var data = Data()
        data.append(TKBERTLVRecord(tag: 0x71, value: currentId).data)
        data.append(TKBERTLVRecord(tag: 0x71, value: renamedId).data)
        let apdu = APDU(cla: 0, ins: 0x05, p1: 0, p2: 0, command: data)
        try await send(apdu: apdu)
    }

    /// Deletes an existing Credential from the YubiKey.
    /// - Parameter credential: The credential that will be deleted from the YubiKey.
    public func deleteCredential(_ credential: Credential) async throws {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(credential)")
        let deleteTlv = TKBERTLVRecord(tag: 0x71, value: credential.id)
        let apdu = APDU(cla: 0, ins: 0x02, p1: 0, p2: 0, command: deleteTlv.data)
        try await send(apdu: apdu)
    }

    /// List credentials on YubiKey
    ///
    /// >Note: The requires touch property of Credential will always be set to false when using `listCredentials()`. If you need this property use ``calculateCodes(timestamp:)`` instead.
    /// - Returns: An array of Credentials.
    public func listCredentials() async throws -> [Credential] {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)")
        let apdu = APDU(cla: 0, ins: 0xa1, p1: 0, p2: 0)
        let data = try await send(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: data) else {
            throw OATHSessionError.responseDataNotTLVFormatted
        }
        return try result.map {
            guard $0.tag == 0x72 else { throw OATHSessionError.unexpectedTag }
            guard let credentialId = CredentialIdParser(data: $0.value.dropFirst()) else {
                throw OATHSessionError.unexpectedData
            }
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

            guard let hashAlgorithm = HashAlgorithm(rawValue: bytes[0] & 0x0f) else {
                throw OATHSessionError.unexpectedData
            }

            return Credential(
                deviceId: selectResponse.deviceId,
                id: $0.value.dropFirst(),
                type: credentialType,
                hashAlgorithm: hashAlgorithm,
                name: credentialId.account,
                issuer: credentialId.issuer,
                requiresTouch: false
            )
        }
    }

    /// Returns a new Code for a stored Credential.
    /// - Parameters:
    ///   - credential: The stored Credential to calculate a new code for.
    ///   - timestamp: The timestamp which is used as start point for TOTP, this is ignored for HOTP.
    /// - Returns: Calculated code.
    public func calculateCode(credential: Credential, timestamp: Date = Date()) async throws -> Code {
        Logger.oath.debug(
            "\(String(describing: self).lastComponent), \(#function): credential: \(credential), timeStamp: \(timestamp)"
        )

        guard credential.deviceId == selectResponse.deviceId else {
            throw OATHSessionError.credentialNotPresentOnCurrentYubiKey
        }
        let challengeTLV: TKBERTLVRecord

        switch credential.type {
        case .HOTP:
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: Data())
        case .TOTP(let period):
            let time = timestamp.timeIntervalSince1970
            let challenge = UInt64(time / Double(period))
            let bigChallenge = CFSwapInt64HostToBig(challenge)
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        }

        let nameTLV = TKBERTLVRecord(tag: tagName, value: credential.id)
        let apdu = APDU(cla: 0x00, ins: 0xa2, p1: 0, p2: 1, command: nameTLV.data + challengeTLV.data, type: .extended)

        let data = try await send(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: data) else { throw OATHSessionError.responseDataNotTLVFormatted }

        guard let digits = result.value.first else { throw OATHSessionError.unexpectedData }
        let code = UInt32(bigEndian: result.value.subdata(in: 1..<result.value.count).uint32)
        let stringCode = String(format: "%0\(digits)d", UInt(code))
        return Code(code: stringCode, timestamp: timestamp, credentialType: credential.type)
    }

    /// Calculate a full (non-truncated) HMAC signature using a credential id.
    ///
    /// Using this command a credential id can be used as an HMAC key to calculate a
    /// result for an arbitrary challenge. The hash algorithm specified for the Credential
    /// is used.
    /// - Parameters:
    ///   - credentialId: The ID of a stored Credential.
    ///   - challenge: The input to the HMAC operation.
    /// - Returns: The calculated response.
    public func calculateResponse(credentialId: Data, challenge: Data) async throws -> Data {
        Logger.oath.debug(
            "\(String(describing: self).lastComponent), \(#function): credentialId: \(credentialId.hexEncodedString), challenge: \(challenge.hexEncodedString)"
        )
        var data = Data()
        data.append(TKBERTLVRecord(tag: tagName, value: credentialId).data)
        data.append(TKBERTLVRecord(tag: tagChallenge, value: challenge).data)
        let apdu = APDU(cla: 0, ins: 0xa2, p1: 0, p2: 0, command: data)
        let result = try await send(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: result) else { throw OATHSessionError.responseDataNotTLVFormatted }
        guard result.tag == tagResponse || result.data.count > 0 else { throw OATHSessionError.badCalculation }
        return result.value.dropFirst()
    }

    /// List all credentials on the YubiKey and calculate each credentials code.
    ///
    /// Credentials which use HOTP, or which require touch, will not be calculated.
    /// They will still be present in the result, but with a nil value.
    /// - Parameter timestamp: The timestamp which is used as start point for TOTP, this is ignored for HOTP.
    /// - Returns: An array of tuples containing a ``Credential`` and an optional ``Code``.
    public func calculateCodes(timestamp: Date = Date()) async throws -> [(Credential, Code?)] {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): timeStamp: \(timestamp)")
        let time = timestamp.timeIntervalSince1970
        let challenge = UInt64(time / 30)
        let bigChallenge = CFSwapInt64HostToBig(challenge)
        let challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        let apdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01, command: challengeTLV.data)
        let data = try await send(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: data)?.tuples() else {
            throw OATHSessionError.responseDataNotTLVFormatted
        }

        var credentialCodePairs: [(Credential, Code?)] = []
        for (name, response) in result {
            guard name.tag == 0x71 else { throw OATHSessionError.unexpectedTag }

            guard let credentialId = CredentialIdParser(data: name.value) else { throw OATHSessionError.unexpectedData }

            let credentialType: CredentialType
            if response.tag == tagTypeHOTP {
                credentialType = .HOTP(counter: 0)
            } else {
                credentialType = .TOTP(period: credentialId.period ?? oathDefaultPeriod)
            }

            let requiresTouch = response.tag == tagTypeTouch

            let credential = Credential(
                deviceId: selectResponse.deviceId,
                id: name.value,
                type: credentialType,
                name: credentialId.account,
                issuer: credentialId.issuer,
                requiresTouch: requiresTouch
            )

            if response.value.count == 5 {
                if credentialId.period != oathDefaultPeriod {
                    let code = try await self.calculateCode(credential: credential, timestamp: timestamp)
                    credentialCodePairs.append((credential, code))
                } else {
                    let digits = response.value.first!
                    let code = UInt32(bigEndian: response.value.subdata(in: 1..<response.value.count).uint32)
                    let stringCode = String(format: "%0\(digits)d", UInt(code))
                    credentialCodePairs.append(
                        (credential, Code(code: stringCode, timestamp: timestamp, credentialType: credentialType))
                    )
                }
            } else {
                credentialCodePairs.append((credential, nil))
            }
        }
        return credentialCodePairs
    }

    /// Sets an Access Key derived from a password. Once a key is set, any usage of the credentials stored will
    /// require the application to be unlocked via one of the unlock functions. Also see ``setAccessKey(_:)``.
    /// - Parameter password: The user-supplied password to set.
    public func setPassword(_ password: String) async throws {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(password)")
        let derivedKey = try deriveAccessKey(from: password)
        try await self.setAccessKey(derivedKey)
    }

    /// Unlock with password.
    /// - Parameter password: The user-supplied password used to unlock the application.
    public func unlockWithPassword(_ password: String) async throws {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(password)")
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
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(accessKey.hexEncodedString)")
        let header = CredentialType.TOTP().code | HashAlgorithm.SHA1.rawValue
        var data = Data([header])
        data.append(accessKey)
        let keyTlv = TKBERTLVRecord(tag: tagSetCodeKey, value: data)

        // Challenge
        let challenge = Data.random(length: 8)
        let challengeTlv = TKBERTLVRecord(tag: tagChallenge, value: challenge)

        // Response
        let response = challenge.hmacSha1(usingKey: accessKey)
        let responseTlv = TKBERTLVRecord(tag: tagResponse, value: response)
        let apdu = APDU(cla: 0, ins: 0x03, p1: 0, p2: 0, command: keyTlv.data + challengeTlv.data + responseTlv.data)
        try await send(apdu: apdu)
    }

    /// Unlock OATH application on the YubiKey. Once unlocked other commands may be sent to the key.
    ///
    /// Once unlocked, the application will remain unlocked for the duration of the session.
    /// See the [YKOATH protocol specification](https://developers.yubico.com/OATH/) for further details.
    /// - Parameter accessKey: The shared access key.
    public func unlockWithAccessKey(_ accessKey: Data) async throws {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(accessKey.hexEncodedString)")
        guard let responseChallenge = self.selectResponse.challenge else { throw SessionError.unexpectedResult }
        let reponseTlv = TKBERTLVRecord(tag: tagResponse, value: responseChallenge.hmacSha1(usingKey: accessKey))
        let challenge = Data.random(length: 8)
        let challengeTlv = TKBERTLVRecord(tag: tagChallenge, value: challenge)
        let apdu = APDU(cla: 0, ins: 0xa3, p1: 0, p2: 0, command: reponseTlv.data + challengeTlv.data)

        do {
            let data = try await connection.send(apdu: apdu)
            guard let resultTlv = TKBERTLVRecord(from: data), resultTlv.tag == tagResponse else {
                throw OATHSessionError.unexpectedTag
            }
            let expectedResult = challenge.hmacSha1(usingKey: accessKey)
            guard resultTlv.value == expectedResult else { throw OATHSessionError.unexpectedData }
        } catch {
            if let reponseError = error as? ResponseError, reponseError.responseStatus.status == .incorrectParameters {
                throw OATHSessionError.wrongPassword
            } else {
                throw error
            }
        }
    }

    /// Removes the access key, if one is set.
    public func deleteAccessKey() async throws {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)")
        let tlv = TKBERTLVRecord(tag: tagSetCodeKey, value: Data())
        let apdu = APDU(cla: 0, ins: 0x03, p1: 0, p2: 0, command: tlv.data)
        try await send(apdu: apdu)
    }

    deinit {
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)")
    }

    @discardableResult
    private func send(apdu: APDU) async throws -> Data {
        if let processor {
            return try await processor.send(apdu: apdu, using: connection, insSendRemaining: 0xa5)
        } else {
            return try await connection.send(apdu: apdu, insSendRemaining: 0xa5)
        }
    }
}

public struct DeriveAccessKeyError: Error {
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
            let status = CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password,
                password.utf8.count,
                selectResponse.salt.bytes,
                selectResponse.salt.bytes.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                1000,
                outputBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                kCCKeySizeAES256
            )
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
