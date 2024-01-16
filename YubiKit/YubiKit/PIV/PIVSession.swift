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
};


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

public final actor PIVSession: Session, InternalSession {
    public var version: Version
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

    
    private func usePrivateKeyInSlot(_ slot: PIVSlot, keyType: PIVKeyType, message: Data, exponentiation: Bool) async throws -> Data {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function): slot: \(String(describing: slot)), type: \(String(describing: keyType)), message: \(message.hexEncodedString), exponentiation: \(exponentiation)")
        guard let connection = _connection else { throw SessionError.noConnection }
        var recordsData = Data()
        recordsData.append(TKBERTLVRecord(tag: tagAuthResponse, value: Data()).data)
        recordsData.append(TKBERTLVRecord(tag: exponentiation ? tagExponentiation : tagChallenge, value: message).data)
        let command = TKBERTLVRecord(tag: tagDynAuth, value: recordsData).data
        let apdu = APDU(cla: 0, ins: insAuthenticate, p1: keyType.rawValue, p2: slot.rawValue, command: command)
        let resultData = try await connection.send(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: resultData), result.tag == tagDynAuth else { throw PIVSessionError.responseDataNotTLVFormatted }
        guard let data = TKBERTLVRecord(from: result.value), data.tag == tagAuthResponse else { throw PIVSessionError.responseDataNotTLVFormatted }
        return data.value
    }

    public func calculateSecretKeyInSlot(slot: PIVSlot, peerPublicKey: SecKey) async throws -> Data {
        guard let keyType = peerPublicKey.type, keyType != .ECCP256, keyType != .ECCP384 else { throw "unsupported key" }
        var error: Unmanaged<CFError>?
        guard let externalRepresentation = SecKeyCopyExternalRepresentation(peerPublicKey, &error) as? Data else {
            throw error!.takeRetainedValue() as Error
        }
        var data = Data()
        data.append(externalRepresentation.subdata(in: 0 ..< 1 + 2 * Int(keyType.size)))
        return try await usePrivateKeyInSlot(slot, keyType: keyType, message: Data(), exponentiation: true)
    }
    
    public func attestKeyInSlot(slot: PIVSlot) async throws -> SecCertificate {
        let apdu = APDU(cla: 0, ins: insAttest, p1: slot.rawValue, p2: 0)
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
            let modulusData = 0x00.data + modulus
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
        let apdu = APDU(cla: 0, ins: insImportKey, p1: keyType.rawValue, p2: slot.rawValue, command: data)
        _ = try await connection.send(apdu: apdu)
        return keyType
    }

}
