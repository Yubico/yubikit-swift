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

/// An interface to the OATH application on the YubiKey.
///
/// The OATHSession is an interface to the OATH application on the YubiKey that will
/// let you store, calculate and edit TOTP and HOTP credentials on the YubiKey. Learn
/// more about OATH on the [Yubico developer website](https://developers.yubico.com/OATH/).
public final actor OATHSession: SmartCardSessionInternal {

    public typealias Feature = OATHSessionFeature
    public typealias Error = OATHSessionError

    static public let application: Application = .oath

    let interface: SmartCardInterface<Error>

    private struct SelectResponse {
        let salt: Data
        let challenge: Data?
        let version: Version
        let deviceId: String
    }

    private let selectResponse: SelectResponse
    /// The firmware version of the connected YubiKey.
    public var version: Version {
        selectResponse.version
    }

    private init(connection: SmartCardConnection, scpKeyParams: SCPKeyParams? = nil) async throws(OATHSessionError) {
        // Create interface with application selection and optional SCP (OATH uses 0xa5 for continuation)
        let interface = try await SmartCardInterface<Error>(
            connection: connection,
            application: .oath,
            keyParams: scpKeyParams,
            insSendRemaining: 0xa5
        )

        // Parse select response
        guard let result = TKBERTLVRecord.dictionaryOfData(from: interface.selectResponse) else {
            throw .responseParseError("Response data not in expected TLV format", source: .here())
        }

        let challenge = result[tagChallenge]

        guard let versionData = result[tagVersion],
            let version = Version(withData: versionData)
        else {
            throw .responseParseError(
                "Missing version information in OATH application select response",
                source: .here()
            )
        }

        guard let salt = result[tagName] else {
            throw .responseParseError("Missing salt in OATH application select response", source: .here())
        }

        let digest = SHA256.hash(data: salt)
        guard digest.data.count >= 16 else { throw .failedDerivingDeviceId(source: .here()) }
        let deviceId = digest.data.subdata(in: 0..<16).base64EncodedString().replacingOccurrences(of: "=", with: "")

        self.selectResponse = SelectResponse(salt: salt, challenge: challenge, version: version, deviceId: deviceId)
        self.interface = interface
    }

    /// Creates a new OATH session with the provided connection.
    ///
    /// - Parameters:
    ///   - connection: The smart card connection to use for this session.
    ///   - scpKeyParams: Optional SCP key parameters for authenticated communication.
    /// - Returns: A new OATH session instance.
    /// - Throws: ``OATHSessionError`` if the OATH application cannot be selected or session creation fails.
    public static func makeSession(
        connection: SmartCardConnection,
        scpKeyParams: SCPKeyParams? = nil
    ) async throws(OATHSessionError) -> OATHSession {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(String(describing: connection))") */
        // Create a new OATHSession
        let session = try await OATHSession(connection: connection, scpKeyParams: scpKeyParams)
        return session
    }

    /// Performs a factory reset of the OATH application, deleting all stored credentials.
    ///
    /// > Warning: This operation is irreversible and will delete all OATH credentials stored on the YubiKey.
    ///
    /// > Important: Calling `reset()` will cause this session to enter an unusable state.
    /// > After reset, the `OATHSession` should be discarded and a new session should be established.
    ///
    /// - Throws: An error if the reset operation fails.
    public func reset() async throws(OATHSessionError) {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)") */
        let apdu = APDU(cla: 0, ins: 0x04, p1: 0xde, p2: 0xad)
        try await process(apdu: apdu)
    }

    /// Checks if the OATH application supports the specified feature.
    ///
    /// - Parameter feature: The feature to check for support.
    /// - Returns: `true` if the feature is supported, `false` otherwise.
    public func supports(_ feature: OATHSession.Feature) async -> Bool {
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
    public func addCredential(template: CredentialTemplate) async throws(OATHSessionError) -> Credential {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)") */
        if template.algorithm == .sha512 {
            guard await self.supports(OATHSessionFeature.sha512) else { throw .featureNotSupported(source: .here()) }
        }
        if template.requiresTouch {
            guard await self.supports(OATHSessionFeature.touch) else { throw .featureNotSupported(source: .here()) }
        }
        guard let nameData = template.identifier.data(using: .utf8) else {
            throw .illegalArgument("Failed to encode credential name", source: .here())
        }
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

        if case let .hotp(counter) = template.type {
            data.append(TKBERTLVRecord(tag: 0x7a, value: counter.data).data)
        }

        let apdu = APDU(cla: 0x00, ins: 0x01, p1: 0x00, p2: 0x00, command: data)
        try await process(apdu: apdu)
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
    /// > Note: This functionality requires support for renaming, available on YubiKey 5.3 or later.
    ///
    /// - Parameters:
    ///   - credential: The credential to rename.
    ///   - newName: The new account name.
    ///   - newIssuer: The new issuer.
    public func renameCredential(
        _ credential: Credential,
        newName: String,
        newIssuer: String?
    ) async throws(OATHSessionError) {
        guard await supports(OATHSessionFeature.rename) else { throw .featureNotSupported(source: .here()) }
        guard
            let currentId = CredentialIdentifier.identifier(
                name: credential.name,
                issuer: credential.issuer,
                type: credential.type
            ).data(using: .utf8),
            let renamedId = CredentialIdentifier.identifier(name: newName, issuer: newIssuer, type: credential.type)
                .data(using: .utf8)
        else { throw .illegalArgument("Failed to encode renamed credential ID", source: .here()) }
        var data = Data()
        data.append(TKBERTLVRecord(tag: 0x71, value: currentId).data)
        data.append(TKBERTLVRecord(tag: 0x71, value: renamedId).data)
        let apdu = APDU(cla: 0, ins: 0x05, p1: 0, p2: 0, command: data)
        try await process(apdu: apdu)
    }

    /// Deletes an existing Credential from the YubiKey.
    /// - Parameter credential: The credential that will be deleted from the YubiKey.
    public func deleteCredential(_ credential: Credential) async throws(OATHSessionError) {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(credential)") */
        let deleteTlv = TKBERTLVRecord(tag: 0x71, value: credential.id)
        let apdu = APDU(cla: 0, ins: 0x02, p1: 0, p2: 0, command: deleteTlv.data)
        try await process(apdu: apdu)
    }

    /// List credentials on YubiKey
    ///
    /// > Note: The `requiresTouch` property of ``Credential`` will always be set to `false` when using `listCredentials()`. If you need this property use ``calculateCredentialCodes(timestamp:)`` instead.
    /// - Returns: An array of Credentials.
    public func listCredentials() async throws(OATHSessionError) -> [Credential] {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)") */
        let apdu = APDU(cla: 0, ins: 0xa1, p1: 0, p2: 0)
        let data = try await process(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: data) else {
            throw .responseParseError("Failed to parse TLV records from list response", source: .here())
        }
        return try result.map { record throws(OATHSessionError) in
            guard record.tag == 0x72 else {
                throw .responseParseError("Unexpected TLV tag in credential list", source: .here())
            }
            guard let credentialId = CredentialIdParser(data: record.value.dropFirst()) else {
                throw .responseParseError("Failed to parse credential data from TLV", source: .here())
            }
            let bytes = record.value.bytes
            let typeCode = bytes[0] & 0xf0
            let credentialType: CredentialType
            if CredentialType.isTOTP(typeCode) {
                credentialType = .totp(period: credentialId.period ?? oathDefaultPeriod)
            } else if CredentialType.isHOTP(typeCode) {
                credentialType = .hotp(counter: 0)
            } else {
                throw .responseParseError("Unexpected credential type value", source: .here())
            }

            guard let hashAlgorithm = HashAlgorithm(rawValue: bytes[0] & 0x0f) else {
                throw .responseParseError("Invalid hash algorithm value", source: .here())
            }

            return Credential(
                deviceId: selectResponse.deviceId,
                id: record.value.dropFirst(),
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
    public func calculateCredentialCode(
        for credential: Credential,
        timestamp: Date = Date()
    ) async throws(OATHSessionError) -> Code {
        /* Fix trace: Logger.oath.debug(
            "\(String(describing: self).lastComponent), \(#function): credential: \(credential), timeStamp: \(timestamp)"
        ) */

        guard credential.deviceId == selectResponse.deviceId else {
            throw .credentialNotPresentOnCurrentYubiKey(source: .here())
        }
        let challengeTLV: TKBERTLVRecord

        switch credential.type {
        case .hotp:
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: Data())
        case .totp(let period):
            let time = timestamp.timeIntervalSince1970
            let challenge = UInt64(time / Double(period))
            let bigChallenge = CFSwapInt64HostToBig(challenge)
            challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        }

        let nameTLV = TKBERTLVRecord(tag: tagName, value: credential.id)
        let apdu = APDU(cla: 0x00, ins: 0xa2, p1: 0, p2: 1, command: nameTLV.data + challengeTLV.data, type: .extended)

        let data = try await process(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: data) else {
            throw .responseParseError("Failed to parse TLV response for code calculation", source: .here())
        }

        guard let digits = result.value.first else {
            throw .responseParseError("Missing digits value in code response", source: .here())
        }
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
    public func calculateCredentialResponse(
        for credentialId: Data,
        challenge: Data
    ) async throws(OATHSessionError) -> Data {
        /* Fix trace: Logger.oath.debug(
            "\(String(describing: self).lastComponent), \(#function): credentialId: \(credentialId.hexEncodedString), challenge: \(challenge.hexEncodedString)"
        ) */
        var data = Data()
        data.append(TKBERTLVRecord(tag: tagName, value: credentialId).data)
        data.append(TKBERTLVRecord(tag: tagChallenge, value: challenge).data)
        let apdu = APDU(cla: 0, ins: 0xa2, p1: 0, p2: 0, command: data)
        let result = try await process(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: result) else {
            throw .responseParseError("Failed to parse TLV response for calculation", source: .here())
        }
        guard result.tag == tagResponse || result.data.count > 0 else {
            throw .responseParseError("Invalid OATH calculation response", source: .here())
        }
        return result.value.dropFirst()
    }

    /// List all credentials on the YubiKey and calculate each credentials code.
    ///
    /// Credentials which use HOTP, or which require touch, will not be calculated.
    /// They will still be present in the result, but with a nil value.
    /// - Parameter timestamp: The timestamp which is used as start point for TOTP, this is ignored for HOTP.
    /// - Returns: An array of tuples containing a ``Credential`` and an optional ``Code``.
    public func calculateCredentialCodes(
        timestamp: Date = Date()
    ) async throws(OATHSessionError) -> [(Credential, Code?)] {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): timeStamp: \(timestamp)") */
        let time = timestamp.timeIntervalSince1970
        let challenge = UInt64(time / 30)
        let bigChallenge = CFSwapInt64HostToBig(challenge)
        let challengeTLV = TKBERTLVRecord(tag: tagChallenge, value: bigChallenge.data)
        let apdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01, command: challengeTLV.data)
        let data = try await process(apdu: apdu)
        guard let result = TKBERTLVRecord.sequenceOfRecords(from: data)?.tuples() else {
            throw .responseParseError("Failed to parse TLV records from calculate all response", source: .here())
        }

        var credentialCodePairs: [(Credential, Code?)] = []
        for (name, response) in result {
            guard name.tag == 0x71 else {
                throw .responseParseError("Unexpected TLV tag for credential name", source: .here())
            }

            guard let credentialId = CredentialIdParser(data: name.value) else {
                throw .responseParseError("Failed to parse credential ID", source: .here())
            }

            let credentialType: CredentialType
            if response.tag == tagTypeHOTP {
                credentialType = .hotp(counter: 0)
            } else {
                credentialType = .totp(period: credentialId.period ?? oathDefaultPeriod)
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
                    let code = try await self.calculateCredentialCode(for: credential, timestamp: timestamp)
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
    public func setPassword(_ password: String) async throws(OATHSessionError) {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(password)") */
        let derivedKey = try deriveAccessKey(from: password)
        try await self.setAccessKey(derivedKey)
    }

    /// Unlock with password.
    /// - Parameter password: The user-supplied password used to unlock the application.
    public func unlock(password: String) async throws(OATHSessionError) {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(password)") */
        let derivedKey = try deriveAccessKey(from: password)
        try await self.unlock(accessKey: derivedKey)
    }

    /// Sets an access key.
    ///
    /// Once an access key is set, any usage of the credentials stored will require the application
    /// to be unlocked via one of the unlock methods, which requires knowledge of the access key.
    /// Typically this key is derived from a password (see ``deriveAccessKey(from:)``). This method
    /// sets the raw 16 byte key.
    /// - Parameter accessKey: The shared secret key used to unlock access to the application.
    public func setAccessKey(_ accessKey: Data) async throws(OATHSessionError) {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(accessKey.hexEncodedString)") */
        let header = CredentialType.totp().code | HashAlgorithm.sha1.rawValue
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
        try await process(apdu: apdu)
    }

    /// Unlock OATH application on the YubiKey. Once unlocked other commands may be sent to the key.
    ///
    /// Once unlocked, the application will remain unlocked for the duration of the session.
    /// See the [YKOATH protocol specification](https://developers.yubico.com/OATH/) for further details.
    /// - Parameter accessKey: The shared access key.
    public func unlock(accessKey: Data) async throws(OATHSessionError) {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(accessKey.hexEncodedString)") */
        guard let responseChallenge = self.selectResponse.challenge else {
            throw .responseParseError("Missing challenge in OATH application select response", source: .here())
        }
        let reponseTlv = TKBERTLVRecord(tag: tagResponse, value: responseChallenge.hmacSha1(usingKey: accessKey))
        let challenge = Data.random(length: 8)
        let challengeTlv = TKBERTLVRecord(tag: tagChallenge, value: challenge)
        let apdu = APDU(cla: 0, ins: 0xa3, p1: 0, p2: 0, command: reponseTlv.data + challengeTlv.data)

        let data: Data
        do {
            data = try await process(apdu: apdu)
        } catch {
            guard case let .failedResponse(responseStatus, _) = error else { throw error }
            if responseStatus.status == .incorrectParameters {
                throw OATHSessionError.invalidPassword(source: .here())
            } else {
                throw error
            }
        }
        guard let resultTlv = TKBERTLVRecord(from: data), resultTlv.tag == tagResponse else {
            throw .responseParseError(
                "Unexpected tag in validate response",
                source: .here()
            )
        }
        let expectedResult = challenge.hmacSha1(usingKey: accessKey)
        guard resultTlv.value == expectedResult else {
            throw .responseParseError(
                "Validation failed: response does not match expected result",
                source: .here()
            )
        }
    }

    /// Removes the access key, if one is set.
    public func deleteAccessKey() async throws(OATHSessionError) {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)") */
        let tlv = TKBERTLVRecord(tag: tagSetCodeKey, value: Data())
        let apdu = APDU(cla: 0, ins: 0x03, p1: 0, p2: 0, command: tlv.data)
        try await process(apdu: apdu)
    }

    deinit {
        /* Fix trace: Logger.oath.debug("\(String(describing: self).lastComponent), \(#function)") */
    }

}

struct DeriveAccessKeyError: Error, Sendable {
    let cryptorStatus: CCCryptorStatus
}

extension OATHSession {

    /// Derives an access key from a password and the device-specific salt. The key is derived by running
    /// 1000 rounds of PBKDF2 using the password and salt as inputs, with a 16 byte output.
    /// - Parameter password: A user-supplied password.
    /// - Returns: Access key for unlocking the session.
    public func deriveAccessKey(from password: String) throws(OATHSessionError) -> Data {
        var derivedKey = Data(count: 16)
        do {
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
                    throw EncryptionError.cryptorError(status)
                }
            }
        } catch {
            let encryptionError = error as! EncryptionError
            throw OATHSessionError.cryptoError(
                "Unable to derive access key",
                error: encryptionError,
                source: .here()
            )
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
