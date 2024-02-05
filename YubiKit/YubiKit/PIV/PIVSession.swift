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
import OSLog
import Gzip

/// Touch policy for PIV application.
public enum PIVTouchPolicy: UInt8 {
    case `default` = 0x0
    case never = 0x1
    case always = 0x2
    case cached = 0x3
}

/// Pin policy for PIV application.
public enum PIVPinPolicy: UInt8 {
    case `default` = 0x0
    case never = 0x1
    case nce = 0x2
    case always = 0x3
};

public enum PIVSlot: UInt8 {
    case authentication = 0x9a
    case signature = 0x9c
    case keyManagement = 0x9d
    case cardAuth = 0x9e
    case attestation = 0xf9
    
    var objectId: Data {
        switch self {
        case .authentication:
            return Data([0x5f, 0xc1, 0x05])
        case .signature:
            return Data([0x5f, 0xc1, 0x0a])
        case .keyManagement:
            return Data([0x5f, 0xc1, 0x0b])
        case .cardAuth:
            return Data([0x5f, 0xc1, 0x01])
        case .attestation:
            return Data([0x5f, 0xff, 0x01])
        }
    }
}

public enum PIVKeyType: UInt8 {
    case RSA1024 = 0x06
    case RSA2048 = 0x07
    case ECCP256 = 0x11
    case ECCP384 = 0x14
    case unknown = 0x00
    
    public init?(_ secKey: SecKey) {
        guard let dict = SecKeyCopyAttributes(secKey) else { return nil }
        let attributes = dict as NSDictionary
        guard let size = attributes[kSecAttrKeySizeInBits] as? Int else { return nil }
        guard let type = attributes[kSecAttrKeyType] as? String else { return nil }
        let secAttrKeyTypeRSA = kSecAttrKeyTypeRSA as String
        let secAttrKeyTypeEC = kSecAttrKeyTypeEC as String
        switch type {
        case secAttrKeyTypeRSA:
            switch size {
            case 1024:
                self = .RSA1024
            case 2048:
                self = .RSA2048
            default:
                return nil
            }
        case secAttrKeyTypeEC:
            switch size {
            case 256:
                self = .ECCP256
            case 384:
                self = .ECCP384
            default:
                return nil
            }
        default:
            return nil
        }
    }
    
    var size: UInt {
        switch (self) {
        case .ECCP256:
            return 256 / 8;
        case .ECCP384:
            return 384 / 8;
        case .RSA1024:
            return 1024 / 8;
        case .RSA2048:
            return 2048 / 8;
        default:
            return 0;
        }
    }
}

public enum PIVVerifyPinResult {
    case success(Int)
    case fail(Int)
    case pinLocked
}

public enum PIVSessionError: Error {
    case invalidCipherTextLength
    case unsupportedOperation
    case dataParseError
    case unknownKeyType
    case invalidPin
    case pinLocked
    case invalidResponse
    case authenticationFailed
    case responseDataNotTLVFormatted
    case failedCreatingCertificate
    case badKeyLength
    case invalidInput
    case unsupportedKeyType
}

public struct PIVManagementKeyMetadata {
    
    public enum PIVTouchPolicy: UInt8 {
        case defaultPolicy = 0x0
        case never = 0x1
        case always = 0x2
        case cached = 0x3
    }
    
    public let isDefault: Bool
    public let keyType: PIVManagementKeyType
    public let touchPolicy: PIVTouchPolicy
}

public struct PIVPinPukMetadata {
    let isDefault: Bool
    let retriesTotal: Int
    let retriesRemaining: Int
}

public enum PIVManagementKeyType: UInt8 {
    case tripleDES = 0x03
    case AES128 = 0x08
    case AES192 = 0x0a
    case AES256 = 0x0c
    
    var keyLength: Int {
        switch self {
        case .tripleDES, .AES192:
            return 24
        case .AES128:
            return 16
        case .AES256:
            return 32
        }
    }
    
    var challengeLength: Int {
        switch self {
        case .tripleDES:
            return 8
        case .AES128, .AES192, .AES256:
            return 16
        }
    }
    
    var ccAlgorithm: UInt32 {
        switch self {
        case .tripleDES:
            return UInt32(kCCAlgorithm3DES)
        case .AES128, .AES192, .AES256:
            return UInt32(kCCAlgorithmAES)
        }
    }
}

public final actor PIVSession: Session, InternalSession {
    
    public var version: Version
    private var currentPinAttempts = 0
    private var maxPinAttempts = 3
    
    private weak var _connection: Connection?
    internal func connection() async -> Connection? {
        return _connection
    }
    internal func setConnection(_ connection: Connection?) async {
        _connection = connection
    }
    
    private init(connection: Connection) async throws {
        try await connection.selectApplication(.piv)
        let versionApdu = APDU(cla: 0, ins: 0xfd, p1: 0, p2: 0)
        guard let version = try await Version(withData: connection.send(apdu: versionApdu)) else {
            throw PIVSessionError.dataParseError
        }
        self.version = version
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(String(describing: version))")
        self._connection = connection
        let internalConnection = await internalConnection()
        await internalConnection?.setSession(self)
    }
    
    public static func session(withConnection connection: Connection) async throws -> PIVSession {
        // Close active session if there is one
        let internalConnection = connection as! InternalConnection
        let currentSession = await internalConnection.session()
        await currentSession?.end()
        // Return new PIVSession
        return try await PIVSession(connection: connection)
    }
    
    public func end() async {
        
    }
    
    public func signWithKeyInSlot(_ slot: PIVSlot, keyType: PIVKeyType, algorithm: SecKeyAlgorithm, message: Data) async throws -> Data {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        let data = try PIVPadding.padData(message, keyType: keyType, algorithm: algorithm)
        return try await usePrivateKeyInSlot(slot, keyType: keyType, message: data, exponentiation: false)
    }
    
    public func decryptWithKeyInSlot(slot: PIVSlot, algorithm: SecKeyAlgorithm, encrypted data: Data) async throws -> Data {
        let keyType: PIVKeyType
        switch data.count {
        case 1024 / 8:
            keyType = .RSA1024
        case 2048 / 8:
            keyType = .RSA2048
        default:
            throw PIVSessionError.invalidCipherTextLength
        }
        let result = try await usePrivateKeyInSlot(slot, keyType: keyType, message: data, exponentiation: false)
        return try PIVPadding.unpadRSAData(result, algorithm: algorithm)
    }
    
    public func calculateSecretKeyInSlot(slot: PIVSlot, peerPublicKey: SecKey) async throws -> Data {
        guard let keyType = peerPublicKey.type, (keyType == .ECCP256 || keyType == .ECCP384) else { throw PIVSessionError.unsupportedKeyType }
        var error: Unmanaged<CFError>?
        guard let externalRepresentation = SecKeyCopyExternalRepresentation(peerPublicKey, &error) as? Data else {
            throw error!.takeRetainedValue() as Error
        }
        let data = externalRepresentation.subdata(in: 0 ..< 1 + 2 * Int(keyType.size))
        return try await usePrivateKeyInSlot(slot, keyType: keyType, message: data, exponentiation: true)
    }
    
    public func attestKeyInSlot(slot: PIVSlot) async throws -> SecCertificate {
        let apdu = APDU(cla: 0, ins: insAttest, p1: slot.rawValue, p2: 0, type: .extended)
        guard let connection = _connection else { throw SessionError.noConnection }
        let result = try await connection.send(apdu: apdu)
        guard let certificate = SecCertificateCreateWithData(nil, result as CFData) else { throw PIVSessionError.dataParseError }
        return certificate
    }
    
    public func generateKeyInSlot(slot: PIVSlot, type: PIVKeyType, pinPolicy: PIVPinPolicy = .default, touchPolicy: PIVTouchPolicy = .default) async throws -> SecKey {
        guard let connection = _connection else { throw SessionError.noConnection }
        let tlv = TKBERTLVRecord(tag: tagGenAlgorithm, value: type.rawValue.data)
        let tlvContainer = TKBERTLVRecord(tag: 0xac, value: tlv.data) // What is 0xac?
        let apdu = APDU(cla: 0, ins: insGenerateAsymetric, p1: 0, p2: slot.rawValue, command: tlvContainer.data)
        let result = try await connection.send(apdu: apdu)
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
              let record = records.recordWithTag(0x7F49),
              let records = TKBERTLVRecord.sequenceOfRecords(from: record.value)
        else { throw PIVSessionError.invalidResponse }
        switch type {
        case .ECCP256, .ECCP384:
            guard let eccKeyData = records.recordWithTag(0x86)?.value else { throw PIVSessionError.invalidResponse }
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                             kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
            var error: Unmanaged<CFError>?
            guard let publicKey = SecKeyCreateWithData(eccKeyData as CFData, attributes, &error) else { throw error!.takeRetainedValue() as Error }
            return publicKey
        case .RSA1024, .RSA2048:
            guard let modulus = records.recordWithTag(0x81)?.value,
                  let exponentData = records.recordWithTag(0x82)?.value
            else { throw PIVSessionError.invalidResponse }
            let modulusData = UInt8(0x00).data + modulus
            var data = Data()
            data.append(TKBERTLVRecord(tag: 0x02, value: modulusData).data)
            data.append(TKBERTLVRecord(tag: 0x02, value: exponentData).data)
            let keyRecord = TKBERTLVRecord(tag: 0x30, value: data)
            let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                             kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
            var error: Unmanaged<CFError>?
            guard let publicKey = SecKeyCreateWithData(keyRecord.data as CFData, attributes, &error) else { throw error!.takeRetainedValue() as Error }
            return publicKey
        case .unknown:
            throw PIVSessionError.unknownKeyType
        }
    }
    
    @discardableResult
    public func putKey(key: SecKey, inSlot slot: PIVSlot, pinPolicy: PIVPinPolicy, touchPolicy: PIVTouchPolicy) async throws -> PIVKeyType {
        guard let connection = _connection else { throw SessionError.noConnection }
        guard let keyType = key.type else { throw PIVSessionError.unknownKeyType }
        var error: Unmanaged<CFError>?
        guard let cfKeyData = SecKeyCopyExternalRepresentation(key, &error) else { throw error!.takeRetainedValue() as Error }
        let keyData = cfKeyData as Data
        var data = Data()
        switch keyType {
        case .RSA1024, .RSA2048:
            guard let recordsData = TKBERTLVRecord(from: keyData),
                  let records = TKBERTLVRecord.sequenceOfRecords(from: recordsData.value)
            else { throw PIVSessionError.dataParseError }
            let primeOne = records[4].value
            let primeTwo = records[5].value
            let exponentOne = records[6].value
            let exponentTwo = records[7].value
            let coefficient = records[8].value
            let length = Int(keyType.size / 2)
            data.append(TKBERTLVRecord(tag: 0x01, value: primeOne.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x02, value: primeTwo.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x03, value: exponentOne.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x04, value: exponentTwo.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x05, value: coefficient.padOrTrim(to: length)).data)
        case .ECCP256, .ECCP384:
            let length = Int(keyType.size)
            let startIndex = 1 + 2 * length
            let privateKeyData = keyData.subdata(in: startIndex ..< startIndex + length)
            data.append(TKBERTLVRecord(tag: 0x06, value: privateKeyData).data)
        case .unknown:
            throw PIVSessionError.unknownKeyType
        }
        if pinPolicy != .default {
            data.append(TKBERTLVRecord(tag: tagPinPolicy, value: pinPolicy.rawValue.data).data)
        }
        if touchPolicy != .default {
            data.append(TKBERTLVRecord(tag: tagTouchpolicy, value: touchPolicy.rawValue.data).data)
        }
        let apdu = APDU(cla: 0, ins: insImportKey, p1: keyType.rawValue, p2: slot.rawValue, command: data, type: .extended)
        _ = try await connection.send(apdu: apdu)
        return keyType
    }
    
    public func putCertificate(certificate: SecCertificate, inSlot slot:PIVSlot, compress: Bool) async throws {
        var certData = SecCertificateCopyData(certificate)
        if compress {
            certData = try (certData as NSData).compressed(using: .zlib)
        }
        var data = Data()
        data.append(TKBERTLVRecord(tag: tagCertificate, value: certData as Data).data)
        let isCompressed = compress ? 1 : 0
        data.append(TKBERTLVRecord(tag: tagCertificateInfo, value: isCompressed.data).data)
        data.append(TKBERTLVRecord(tag: tagLRC, value: Data()).data)
        _ = try await self.putObject(data, objectId: slot.objectId)
        
    }
    
    public func getCertificateInSlot(_ slot: PIVSlot) async throws -> SecCertificate {
        guard let connection = _connection else { throw SessionError.noConnection }
        let command = TKBERTLVRecord(tag: tagObjectId, value: slot.objectId).data
        let apdu = APDU(cla: 0, ins: insGetData, p1: 0x3f, p2: 0xff, command: command)
        let result = try await connection.send(apdu: apdu)
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
              let objectData = records.recordWithTag(tagObjectData)?.value,
              let subRecords = TKBERTLVRecord.sequenceOfRecords(from: objectData),
              var certificateData = subRecords.recordWithTag(tagCertificate)?.data
        else { throw PIVSessionError.dataParseError }
        
        if let certificateInfo = subRecords.recordWithTag(tagCertificateInfo)?.data,
           !certificateInfo.isEmpty,
           certificateInfo.bytes[0] == 1 {
            certificateData = try certificateData.gunzipped()
        }
        guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else { throw PIVSessionError.failedCreatingCertificate }
        return certificate
    }
    
    public func deleteCertificateInSlot(slot: PIVSlot) async throws {
        _ = try await putObject(Data(), objectId: slot.objectId)
    }
    
    public func setManagementKey(_ managementKeyData: Data, type: PIVManagementKeyType, requiresTouch: Bool) async throws -> Data {
        guard let connection = _connection else { throw SessionError.noConnection }
        let tlv = TKBERTLVRecord(tag: tagSlotCardManagement, value: managementKeyData)
        var data = Data([type.rawValue])
        data.append(tlv.data)
        let apdu = APDU(cla: 0, ins: insSetManagementKey, p1: 0xff, p2: requiresTouch ? 0xfe : 0xff, command: data, type: .short)
        return try await connection.send(apdu: apdu)
    }
    
    public func authenticateWith(managementKey: Data, keyType: PIVManagementKeyType) async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        guard keyType.keyLength == managementKey.count else { throw PIVSessionError.badKeyLength }
        
        let witness = TKBERTLVRecord(tag: tagAuthWitness, value: Data()).data
        let command = TKBERTLVRecord(tag: tagDynAuth, value: witness).data
        let witnessApdu = APDU(cla: 0, ins: insAuthenticate, p1: keyType.rawValue, p2: UInt8(tagSlotCardManagement), command: command, type: .extended)
        let witnessResult = try await connection.send(apdu: witnessApdu)
        
        guard let dynAuthRecord = TKBERTLVRecord(from: witnessResult),
              dynAuthRecord.tag == tagDynAuth,
              let witnessRecord = TKBERTLVRecord(from: dynAuthRecord.value),
              witnessRecord.tag == tagAuthWitness
        else { throw PIVSessionError.responseDataNotTLVFormatted }
        let decryptedWitness = try witnessRecord.value.decrypt(algorithm: keyType.ccAlgorithm, key: managementKey)
        let decryptedWitnessRecord = TKBERTLVRecord(tag: tagAuthWitness, value: decryptedWitness)
        let challengeSent = Data.random(length: keyType.challengeLength)
        let challengeRecord = TKBERTLVRecord(tag: tagChallenge, value: challengeSent)
        var data = Data()
        data.append(decryptedWitnessRecord.data)
        data.append(challengeRecord.data)
        let authRecord = TKBERTLVRecord(tag: tagDynAuth, value: data)
        let challengeApdu = APDU(cla: 0, ins: insAuthenticate, p1: keyType.rawValue, p2: UInt8(tagSlotCardManagement), command: authRecord.data, type: .extended)
        let challengeResult = try await connection.send(apdu: challengeApdu)
        
        guard let dynAuthRecord = TKBERTLVRecord(from: challengeResult),
              dynAuthRecord.tag == tagDynAuth,
              let encryptedChallengeRecord = TKBERTLVRecord(from: dynAuthRecord.value),
              encryptedChallengeRecord.tag == tagAuthResponse
        else { throw PIVSessionError.responseDataNotTLVFormatted }
        let challengeReturned = try encryptedChallengeRecord.value.decrypt(algorithm: keyType.ccAlgorithm, key: managementKey)
        guard challengeSent == challengeReturned else { throw PIVSessionError.authenticationFailed }
    }
    
    
    public func reset() async throws {
        try await blockPin()
        try await blockPuk()
        guard let connection = _connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: insReset, p1: 0, p2: 0)
        _ = try await connection.send(apdu: apdu)
    }
    
    public func serialNumber() async throws -> UInt32 {
        guard let connection = _connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: insGetSerial, p1: 0, p2: 0)
        let result = try await connection.send(apdu: apdu)
        return CFSwapInt32BigToHost(result.uint32)
    }
    
    @discardableResult
    public func verifyPin(_ pin: String) async throws -> PIVVerifyPinResult {
        guard let connection = _connection else { throw SessionError.noConnection }
        guard let pinData = pin.paddedPinData() else { throw PIVSessionError.invalidPin }
        let apdu = APDU(cla: 0, ins: insVerify, p1: 0, p2: 0x80, command: pinData)
        do {
            _ = try await connection.send(apdu: apdu)
            currentPinAttempts = maxPinAttempts
            return .success(currentPinAttempts)
        } catch {
            guard let responseError = error as? ResponseError //,
            else { throw error }
            if let retriesLeft = responseError.responseStatus.pinRetriesLeft(version: self.version) {
                if retriesLeft > 0 {
                    return .fail(retriesLeft)
                } else {
                    return .pinLocked
                }
            }
            throw PIVSessionError.authenticationFailed
        }
    }
    
    public func setPin(_ newPin: String, oldPin: String) async throws {
        return try await _ = changeReference(ins: insChangeReference, p2: p2Pin, valueOne: oldPin, valueTwo: newPin)
    }

    public func setPuk(_ newPuk: String, oldPuk: String) async throws {
        return try await _ = changeReference(ins: insChangeReference, p2: p2Puk, valueOne: oldPuk, valueTwo: newPuk)
    }
    
    public func unblockPinWithPuk(_ puk: String, newPin: String) async throws {
        return try await _ = changeReference(ins: insResetRetry, p2: p2Pin, valueOne: puk, valueTwo: newPin)
    }


    
    public func getPinMetadata() async throws -> PIVPinPukMetadata {
        try await getPinPukMetadata(p2: p2Pin)
    }
    
    public func getPukMetadata() async throws -> PIVPinPukMetadata {
        try await getPinPukMetadata(p2: p2Puk)
    }
    
    public func getManagementKeyMetadataWithCompletion() async throws -> PIVManagementKeyMetadata {
        guard let connection = _connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: insGetMetadata, p1: 0, p2: p2SlotCardmanagement)
        let result = try await connection.send(apdu: apdu)
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
              let isDefault = records.recordWithTag(tagMetadataDefault)?.value.bytes[0],
              let rawTouchPolicy = records.recordWithTag(tagMetadataTouchPolicy)?.value.bytes[1],
              let touchPolicy = PIVManagementKeyMetadata.PIVTouchPolicy(rawValue: rawTouchPolicy)
        else { throw PIVSessionError.responseDataNotTLVFormatted }
        
        let keyType: PIVManagementKeyType
        if let rawKeyType = records.recordWithTag(tagMetadataAlgorithm)?.value.bytes[0] {
            guard let parsedKeyType = PIVManagementKeyType(rawValue: rawKeyType) else { throw PIVSessionError.unknownKeyType }
            keyType = parsedKeyType
        } else {
            keyType = .tripleDES
        }
        return PIVManagementKeyMetadata(isDefault: isDefault != 0, keyType: keyType, touchPolicy: touchPolicy)
    }
    
    public func getPinAttempts() async throws -> Int {
        guard let connection = _connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: insVerify, p1: 0, p2: p2Pin)
        do {
            _ = try await connection.send(apdu: apdu)
            return currentPinAttempts
        } catch {
            guard let responseError = error as? ResponseError else { throw error }
            let retries = retriesFrom(responseError: responseError)
            if retries < 0 {
                throw error
            } else {
                return retries
            }
        }
    }
    
    public func setPinAttempts(_ pinAttempts: Int, pukAttempts: Int) async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        guard let pinAttempts = UInt8(exactly: pinAttempts),
              let pukAttempts = UInt8(exactly: pukAttempts) else { throw PIVSessionError.invalidInput }
        let apdu = APDU(cla: 0, ins: insSetPinPukAttempts, p1: pinAttempts, p2: pukAttempts)
        _ = try await connection.send(apdu: apdu)
        maxPinAttempts = Int(pinAttempts)
        currentPinAttempts = Int(pinAttempts)
    }
    
    public func blockPin(counter: Int = 0) async throws {
        let result = try await verifyPin("")
        switch result {
        case .success(_), .fail(_):
            if counter < 15 {
                try await blockPin(counter: counter + 1)
            }
        case .pinLocked:
            return
        }
    }
    
    public func blockPuk(counter: Int = 0) async throws {
        let retries = try await changeReference(ins: insResetRetry, p2: p2Pin, valueOne: "", valueTwo: "")
        if retries <= 0 || counter > 15 {
            return
        } else {
            try await blockPuk(counter: counter + 1)
        }
    }
    
}




extension PIVSession {
    
    private func usePrivateKeyInSlot(_ slot: PIVSlot, keyType: PIVKeyType, message: Data, exponentiation: Bool) async throws -> Data {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function): slot: \(String(describing: slot)), type: \(String(describing: keyType)), message: \(message.hexEncodedString), exponentiation: \(exponentiation)")
        guard let connection = _connection else { throw SessionError.noConnection }
        var recordsData = Data()
        recordsData.append(TKBERTLVRecord(tag: tagAuthResponse, value: Data()).data)
        recordsData.append(TKBERTLVRecord(tag: exponentiation ? tagExponentiation : tagChallenge, value: message).data)
        let command = TKBERTLVRecord(tag: tagDynAuth, value: recordsData).data
        let apdu = APDU(cla: 0, ins: insAuthenticate, p1: keyType.rawValue, p2: slot.rawValue, command: command, type: .extended)
        let resultData = try await connection.send(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: resultData), result.tag == tagDynAuth else { throw PIVSessionError.responseDataNotTLVFormatted }
        guard let data = TKBERTLVRecord(from: result.value), data.tag == tagAuthResponse else { throw PIVSessionError.responseDataNotTLVFormatted }
        return data.value
    }
    
    private func putObject(_ data: Data, objectId: Data) async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        var data = Data()
        data.append(TKBERTLVRecord(tag: tagObjectId, value: objectId).data)
        data.append(TKBERTLVRecord(tag: tagObjectData, value: data).data)
        let apdu = APDU(cla: 0, ins: insPutData, p1: 0x3f, p2: 0xff, command: data, type: .extended)
        _ = try await connection.send(apdu: apdu)
    }
    
    private func changeReference(ins: UInt8, p2: UInt8, valueOne: String, valueTwo: String) async throws -> Int {
        guard let connection = _connection else { throw SessionError.noConnection }
        guard let paddedValueOne = valueOne.paddedPinData(), let paddedValueTwo = valueTwo.paddedPinData() else { throw PIVSessionError.invalidPin }
        let data = paddedValueOne + paddedValueTwo
        let apdu = APDU(cla: 0, ins: ins, p1: 0, p2: p2, command: data)
        do {
            let _ = try await connection.send(apdu: apdu)
            return currentPinAttempts
        } catch {
            guard let responseError = error as? ResponseError else { throw PIVSessionError.invalidResponse }
            let retries = retriesFrom(responseError: responseError)
            if retries >= 0 {
                if p2 == 0x80 {
                    currentPinAttempts = retries;
                }
            }
            return retries
        }
    }
    
    private func getPinPukMetadata(p2: UInt8) async throws -> PIVPinPukMetadata {
        guard let connection = _connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0, ins: insGetMetadata, p1: 0, p2: p2)
        let result = try await connection.send(apdu: apdu)
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
              let isDefault = records.recordWithTag(tagMetadataDefault)?.value.bytes[0],
              let retriesTotal = records.recordWithTag(tagMetadataRetries)?.value.bytes[0],
              let retriesRemaining = records.recordWithTag(tagMetadataRetries)?.value.bytes[1]
        else { throw PIVSessionError.responseDataNotTLVFormatted }
        
        return PIVPinPukMetadata(isDefault: isDefault != 0, retriesTotal: Int(retriesTotal), retriesRemaining: Int(retriesRemaining))
    }
    
    private func retriesFrom(responseError: ResponseError) -> Int {
        let statusCode = responseError.responseStatus.rawStatus
        if statusCode == 0x6983 {
            return 0
        } else if self.version > Version(withString: "1.0.4")! {
            if statusCode >= 0x6300 && statusCode <= 0x63ff {
                return Int(statusCode & 0xff);
            }
        } else {
            if statusCode >= 0x63c0 && statusCode <= 0x63cf {
                return Int(statusCode & 0xf);
            }
        }
        return -1
    }
}




fileprivate extension ResponseStatus {
    func pinRetriesLeft(version: Version) -> Int? {
        if (self.rawStatus == 0x6983) {
            print("hepp")
            return 0;
        }
        if version < Version(withString: "1.0.4")! {
            if (self.rawStatus >= 0x6300 && self.rawStatus <= 0x63ff) {
                return Int(self.rawStatus & 0xff);
            }
        } else {
            if (self.rawStatus >= 0x63c0 && self.rawStatus <= 0x63cf) {
                return Int(self.rawStatus & 0xf);
            }
        }
        return nil
    }
}

fileprivate extension String {
    func paddedPinData() -> Data? {
        guard var data = self.data(using: .utf8) else { return nil }
        let paddingSize = 8 - data.count
        for _ in 0..<paddingSize {
            data.append(0xff)
        }
        return data
    }
}


// Special slot for the management key
fileprivate let tagSlotCardManagement: TKTLVTag = 0x9b;

// Instructions
fileprivate let insAuthenticate: UInt8 = 0x87
fileprivate let insVerify: UInt8 = 0x20
fileprivate let insReset: UInt8 = 0xfb
fileprivate let insGetVersion: UInt8 = 0xfd
fileprivate let insGetSerial: UInt8 = 0xf8
fileprivate let insGetMetadata: UInt8 = 0xf7
fileprivate let insGetData: UInt8 = 0xcb
fileprivate let insPutData: UInt8 = 0xdb
fileprivate let insImportKey: UInt8 = 0xfe
fileprivate let insChangeReference: UInt8 = 0x24
fileprivate let insResetRetry: UInt8 = 0x2c
fileprivate let insSetManagementKey: UInt8 = 0xff
fileprivate let insSetPinPukAttempts: UInt8 = 0xfa
fileprivate let insGenerateAsymetric: UInt8 = 0x47;
fileprivate let insAttest: UInt8 = 0xf9;

// Tags
fileprivate let tagMetadataDefault: TKTLVTag = 0x05
fileprivate let tagMetadataAlgorithm: TKTLVTag = 0x01
fileprivate let tagMetadataTouchPolicy: TKTLVTag = 0x02
fileprivate let tagMetadataRetries: TKTLVTag = 0x06
fileprivate let tagDynAuth: TKTLVTag = 0x7c
fileprivate let tagAuthWitness: TKTLVTag = 0x80
fileprivate let tagChallenge: TKTLVTag = 0x81
fileprivate let tagExponentiation: TKTLVTag = 0x85
fileprivate let tagAuthResponse: TKTLVTag = 0x82
fileprivate let tagGenAlgorithm: TKTLVTag = 0x80
fileprivate let tagObjectData: TKTLVTag = 0x53
fileprivate let tagObjectId: TKTLVTag = 0x5c
fileprivate let tagCertificate: TKTLVTag = 0x70
fileprivate let tagCertificateInfo: TKTLVTag = 0x71
fileprivate let tagLRC: TKTLVTag = 0xfe
fileprivate let tagPinPolicy: TKTLVTag = 0xaa
fileprivate let tagTouchpolicy: TKTLVTag = 0xab

// P2
fileprivate let p2Pin: UInt8 = 0x80
fileprivate let p2Puk: UInt8 = 0x81
fileprivate let p2SlotCardmanagement: UInt8 = 0x9b
