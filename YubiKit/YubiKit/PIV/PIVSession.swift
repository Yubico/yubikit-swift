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

/// An interface to the PIV application on the YubiKey.
///
/// The PIVSession is an interface to the Personal Identity Verification (PIV) application on the YubiKey.
/// It supports importing, generating and using private keys. Reading and writing data objects such as
/// X.509 certificates and managing access (PIN, PUK, etc). Learn more about the PIV standard in the NIST SP 800-78
/// [Cryptographic Algorithms and Key Sizes for PIV](https://csrc.nist.gov/publications/detail/sp/800-78/4/final) document.

public final actor PIVSession: Session {

    nonisolated public let version: Version
    private var currentPinAttempts = 0
    private var maxPinAttempts = 3

    private let connection: Connection
    private let processor: SCPProcessor?

    private init(connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws {
        try await connection.selectApplication(.piv)
        let versionApdu = APDU(cla: 0, ins: 0xfd, p1: 0, p2: 0)
        guard let version = try await Version(withData: connection.send(apdu: versionApdu)) else {
            throw PIVSessionError.dataParseError
        }
        self.version = version
        if let scpKeyParams {
            processor = try await SCPProcessor(connection: connection, keyParams: scpKeyParams)
        } else {
            processor = nil
        }
        self.connection = connection
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(String(describing: version))")
    }

    public static func session(
        withConnection connection: Connection,
        scpKeyParams: SCPKeyParams? = nil
    ) async throws -> PIVSession {
        // Return new PIVSession
        try await PIVSession(connection: connection, scpKeyParams: scpKeyParams)
    }

    nonisolated public func supports(_ feature: SessionFeature) -> Bool {
        feature.isSupported(by: version)
    }

    /// Create a signature for a given message.
    /// - Parameters:
    ///   - slot: The slot containing the private key to use.
    ///   - keyType: The type of RSA key stored in the slot.
    ///   - algorithm: The signing algorithm, which specifies both the key type and hash algorithm.
    ///   - message: The message to sign.
    /// - Returns: The generated signature for the message.
    public func sign(
        slot: PIVSlot,
        keyType: PIVRSAKey,
        algorithm: PIVRSASignatureAlgorithm,
        message: Data
    ) async throws -> Data {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")

        let signature = try PIVDataFormatter.prepareDataForRSASigning(
            message,
            keySize: keyType.keysize,
            algorithm: algorithm
        )

        return try await usePrivateKeyInSlot(
            slot: slot,
            keyType: .rsa(keyType.keysize),
            message: signature,
            exponentiation: false
        )
    }

    /// Create a signature for a given message.
    /// - Parameters:
    ///   - slot: The slot containing the private key to use.
    ///   - keyType: The type of ECC key stored in the slot.
    ///   - algorithm: The ECDSA signature algorithm to use.
    ///   - message: The message to sign.
    /// - Returns: The generated signature for the message.
    public func sign(
        slot: PIVSlot,
        keyType: PIVECCKey,
        algorithm: PIVECDSASignatureAlgorithm,
        message: Data
    ) async throws -> Data {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")

        let signature = try PIVDataFormatter.prepareDataForECDSASigning(
            message,
            curve: keyType.curve,
            algorithm: algorithm
        )

        return try await usePrivateKeyInSlot(
            slot: slot,
            keyType: .ecc(keyType.curve),
            message: signature,
            exponentiation: false
        )
    }

    /// Create a signature for a given message.
    /// - Parameters:
    ///   - slot: The slot containing the private key to use.
    ///   - keyType: The type of Ed25519 key stored in the slot.
    ///   - message: The message to sign.
    /// - Returns: The generated signature for the message.
    public func sign(
        slot: PIVSlot,
        keyType: PIVEd25519Key,
        message: Data
    ) async throws -> Data {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")

        return try await usePrivateKeyInSlot(slot: slot, keyType: .ed25519, message: message, exponentiation: false)
    }

    /// Decrypts a RSA-encrypted message.
    /// - Parameters:
    ///   - slot: The slot containing the private key to use.
    ///   - algorithm: The same algorithm used when signing.
    ///   - data: The encrypted data to decrypt.
    /// - Returns: The decrypted data.
    public func decryptWithKeyInSlot(
        slot: PIVSlot,
        algorithm: PIVRSAEncryptionAlgorithm,
        encrypted data: Data
    ) async throws -> Data {
        let validTypes = RSA.KeySize.allCases.compactMap { PIVKeyType(kind: .rsa($0)) }
        guard let keyType = validTypes.first(where: { $0.sizeInBytes == data.count }) else {
            throw PIVSessionError.invalidCipherTextLength
        }
        let result = try await usePrivateKeyInSlot(slot: slot, keyType: keyType, message: data, exponentiation: false)
        return try PIVDataFormatter.extractDataFromRSAEncryption(result, algorithm: algorithm)
    }

    /// Perform an ECDH operation with a given public key to compute a shared secret.
    /// - Parameters:
    ///   - slot: The slot containing the private EC key to use.
    ///   - peerKey: The peer public key for the operation.
    /// - Returns: The shared secret.
    public func calculateSecretKeyInSlot(slot: PIVSlot, peerKey: EC.PublicKey) async throws -> Data {

        try await usePrivateKeyInSlot(
            slot: slot,
            keyType: .ecc(peerKey.curve),
            message: peerKey.uncompressedPoint,
            exponentiation: true
        )
    }

    /// Perform an X25519 key agreement operation with a given public key to compute a shared secret.
    /// - Parameters:
    ///   - slot: The slot containing the private X25519 key to use.
    ///   - peerKey: The peer public key for the operation.
    /// - Returns: The shared secret.
    public func calculateSecretKeyInSlot(slot: PIVSlot, peerKey: Curve25519.X25519.PublicKey) async throws -> Data {

        try await usePrivateKeyInSlot(
            slot: slot,
            keyType: .x25519,
            message: peerKey.keyData,
            exponentiation: true
        )
    }

    /// Creates an attestation certificate for a private key which was generated on the YubiKey.
    ///
    /// A high level description of the thinking and how this can be used can be found at
    /// [](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html).
    /// Attestation works through a special key slot called "f9" this comes pre-loaded from factory
    /// with a key and cert signed by Yubico, but can be overwritten. After a key has been generated
    /// in a normal slot it can be attested by this special key
    ///
    /// This method requires authentication.
    ///
    /// >Note: This functionality requires support for attestation, available on YubiKey 4.3 or later.
    ///
    /// - Parameter slot: The slot containing the private key to use.
    /// - Returns: The attestation certificate.
    public func attestKeyInSlot(slot: PIVSlot) async throws -> X509Cert {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard self.supports(PIVSessionFeature.attestation) else { throw SessionError.notSupported }
        let apdu = APDU(cla: 0, ins: insAttest, p1: slot.rawValue, p2: 0)
        let result = try await send(apdu: apdu)
        return X509Cert(der: result)
    }

    /// Generates a new key pair within the YubiKey.
    ///
    /// This method requires authentication and pin verification.
    ///
    /// >Note: YubiKey FIPS does not allow RSA1024 nor `PIVPinPolicy.never`.
    ///        RSA key types require RSA generation, available on YubiKeys OTHER THAN 4.2.6-4.3.4.
    ///        `PIVKeyType.ECCP348` requires P384 support, available on YubiKey 4 or later.
    ///        Ed25519 and X25519 require YubiKey 5.7 or later.
    ///        ``PIVPinPolicy`` or ``PIVTouchPolicy`` other than `defaultPolicy` require support for usage policy, available on YubiKey 4 or later.
    ///        `PIVTouchPolicy.cached` requires support for touch cached, available on YubiKey 4.3 or later.
    ///
    /// - Parameters:
    ///   - slot: The slot to generate the new key in.
    ///   - type: The key type that should be generated.
    ///   - pinPolicy: The PIN policy for using the private key.
    ///   - touchPolicy: The touch policy for using the private key.
    /// - Returns: The generated public key.
    public func generateKeyInSlot(
        slot: PIVSlot,
        type: PIVKeyType,
        pinPolicy: PIVPinPolicy = .defaultPolicy,
        touchPolicy: PIVTouchPolicy = .`defaultPolicy`
    ) async throws -> PublicKey {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        try await checkKeyFeatures(keyType: type, pinPolicy: pinPolicy, touchPolicy: touchPolicy, generateKey: true)
        let records: [TKBERTLVRecord] = [
            TKBERTLVRecord(tag: tagGenAlgorithm, value: type.rawValue.data),
            pinPolicy != .`defaultPolicy` ? TKBERTLVRecord(tag: tagPinPolicy, value: pinPolicy.rawValue.data) : nil,
            touchPolicy != .`defaultPolicy`
                ? TKBERTLVRecord(tag: tagTouchpolicy, value: touchPolicy.rawValue.data) : nil,
        ].compactMap { $0 }
        let tlvContainer = TKBERTLVRecord(tag: 0xac, records: records)
        let apdu = APDU(cla: 0, ins: insGenerateAsymetric, p1: 0, p2: slot.rawValue, command: tlvContainer.data)
        let result = try await send(apdu: apdu)
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
            let record = records.recordWithTag(0x7F49)
        else { throw PIVSessionError.invalidResponse }
        return try publicKey(from: record.value, type: type)
    }

    /// Import a private key into a slot.
    ///
    /// This method requires authentication.
    ///
    /// >Note: YubiKey FIPS does not allow RSA1024 nor `PIVPinPolicy.never`.
    ///        `PIVKeyType.ECCP348` requires P384 support, available on YubiKey 4 or later.
    ///        Ed25519 and X25519 require YubiKey 5.7 or later.
    ///        ``PIVPinPolicy`` or ``PIVTouchPolicy`` other than `defaultPolicy` require support for usage policy,
    ///        available on YubiKey 4 or later.
    ///
    /// - Parameters:
    ///   - key: The private key to import.
    ///   - slot: The slot to write the key to.
    ///   - pinPolicy: The PIN policy for using the private key.
    ///   - touchPolicy: The touch policy for using the private key.
    /// - Returns: The type of the stored key.
    @discardableResult
    public func putKey(
        key: PrivateKey,
        inSlot slot: PIVSlot,
        pinPolicy: PIVPinPolicy,
        touchPolicy: PIVTouchPolicy
    ) async throws -> PIVKeyType {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard let keyType: PIVKeyType = .init(kind: key.kind) else { throw PIVSessionError.unknownKeyType }
        try await checkKeyFeatures(keyType: keyType, pinPolicy: pinPolicy, touchPolicy: touchPolicy, generateKey: false)

        var data = Data()
        switch keyType {
        case .rsa:
            guard let key = key.asRSA() else {
                throw PIVSessionError.unknownKeyType
            }

            let primeOne = key.p
            let primeTwo = key.q
            let exponentOne = key.dP
            let exponentTwo = key.dQ
            let coefficient = key.qInv
            let length = keyType.sizeInBytes / 2
            data.append(TKBERTLVRecord(tag: 0x01, value: primeOne.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x02, value: primeTwo.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x03, value: exponentOne.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x04, value: exponentTwo.padOrTrim(to: length)).data)
            data.append(TKBERTLVRecord(tag: 0x05, value: coefficient.padOrTrim(to: length)).data)
        case .ecc:
            guard let key = key.asEC() else {
                throw PIVSessionError.unknownKeyType
            }

            let privateKeyData = key.k
            data.append(TKBERTLVRecord(tag: 0x06, value: privateKeyData).data)
        case .ed25519:
            guard let key = key.asEd25519() else {
                throw PIVSessionError.unknownKeyType
            }

            let privateKeyData = key.seed
            data.append(TKBERTLVRecord(tag: 0x07, value: privateKeyData).data)
        case .x25519:
            guard let key = key.asX25519() else {
                throw PIVSessionError.unknownKeyType
            }

            let privateKeyData = key.scalar
            data.append(TKBERTLVRecord(tag: 0x08, value: privateKeyData).data)
        }
        if pinPolicy != .`defaultPolicy` {
            data.append(TKBERTLVRecord(tag: tagPinPolicy, value: pinPolicy.rawValue.data).data)
        }
        if touchPolicy != .`defaultPolicy` {
            data.append(TKBERTLVRecord(tag: tagTouchpolicy, value: touchPolicy.rawValue.data).data)
        }
        let apdu = APDU(
            cla: 0,
            ins: insImportKey,
            p1: keyType.rawValue,
            p2: slot.rawValue,
            command: data,
            type: .extended
        )
        try await send(apdu: apdu)
        return keyType
    }

    /// Move key from one slot to another. The source slot must not be the attestation slot and the
    /// destination slot must be empty. This method requires authentication with the management key.
    ///
    /// - Parameters:
    ///   - sourceSlot: Slot to move the key from.
    ///   - destinationSlot: Slot to move the key to.
    public func moveKey(sourceSlot: PIVSlot, destinationSlot: PIVSlot) async throws {
        guard self.supports(PIVSessionFeature.moveDelete) else { throw SessionError.notSupported }
        guard sourceSlot != PIVSlot.attestation else { throw SessionError.illegalArgument }
        Logger.piv.debug(
            "Move key from \(String(describing: sourceSlot)) to \(String(describing: destinationSlot)), \(#function)"
        )
        let apdu = APDU(cla: 0, ins: insMoveKey, p1: destinationSlot.rawValue, p2: sourceSlot.rawValue)
        try await send(apdu: apdu)
    }

    /// Delete key from slot. This method requires authentication with the management key.
    ///
    /// - Parameter slot: Slot to delete the key from.
    public func deleteKey(in slot: PIVSlot) async throws {
        guard self.supports(PIVSessionFeature.moveDelete) else { throw SessionError.notSupported }
        Logger.piv.debug("Delete key in \(String(describing: slot)), \(#function)")
        let apdu = APDU(cla: 0, ins: insMoveKey, p1: 0xff, p2: slot.rawValue)
        try await send(apdu: apdu)
    }

    /// Writes an X.509 certificate to a slot on the YubiKey.
    ///
    /// This method requires authentication.
    ///
    /// >Note: YubiKey FIPS does not allow RSA1024 nor `PIVPinProtocol.never`.
    ///        RSA key types require RSA generation, available on YubiKeys OTHER THAN 4.2.6-4.3.4.
    ///        `PIVKeyType.ECCP348` requires P384 support, available on YubiKey 4 or later.
    ///        ``PIVPinPolicy`` or ``PIVTouchPolicy`` other than `defaultPolicy` require support for usage policy, available on YubiKey 4 or later.
    ///        `PIVTouchPolicy.cached` requires support for touch cached, available on YubiKey 4.3 or later.
    ///
    /// - Parameters:
    ///   - certificate: Certificate to write.
    ///   - slot: The slot to write the certificate to.
    ///   - compress: If true the certificate will be compressed before being stored on the YubiKey.
    public func putCertificate(certificate: X509Cert, inSlot slot: PIVSlot, compress: Bool = false) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        var certData = certificate.der
        if compress {
            certData = try certData.gzipped()
        }
        var data = Data()
        data.append(TKBERTLVRecord(tag: tagCertificate, value: certData).data)
        let isCompressed: UInt8 = compress ? 1 : 0
        data.append(TKBERTLVRecord(tag: tagCertificateInfo, value: isCompressed.data).data)
        data.append(TKBERTLVRecord(tag: tagLRC, value: Data()).data)
        try await self.putObject(data, objectId: slot.objectId)
    }

    /// Reads the X.509 certificate stored in the specified slot on the YubiKey.
    /// - Parameter slot: The slot where the certificate is stored.
    /// - Returns: The X.509 certificate.
    public func getCertificateInSlot(_ slot: PIVSlot) async throws -> X509Cert {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        let command = TKBERTLVRecord(tag: tagObjectId, value: slot.objectId).data
        let apdu = APDU(cla: 0, ins: insGetData, p1: 0x3f, p2: 0xff, command: command, type: .extended)
        let result = try await send(apdu: apdu)

        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
            let objectData = records.recordWithTag(tagObjectData)?.value,
            let subRecords = TKBERTLVRecord.sequenceOfRecords(from: objectData),
            var certificateData = subRecords.recordWithTag(tagCertificate)?.value
        else { throw PIVSessionError.dataParseError }

        if let certificateInfo = subRecords.recordWithTag(tagCertificateInfo)?.value,
            !certificateInfo.isEmpty,
            certificateInfo.bytes[0] == 1
        {
            certificateData = try certificateData.gunzipped()
        }
        return X509Cert(der: certificateData)
    }

    /// Deletes the X.509 certificate stored in the specified slot on the YubiKey.
    ///
    /// This method requires authentication.
    ///
    /// >Note: This does NOT delete any corresponding private key.
    ///
    /// - Parameter slot: The slot where the certificate is stored.
    public func deleteCertificateInSlot(slot: PIVSlot) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        try await putObject(Data(), objectId: slot.objectId)
    }

    /// Set a new management key.
    /// - Parameters:
    ///   - managementKeyData: The new management key as Data.
    ///   - type: The management key type.
    ///   - requiresTouch: Set to true to require touch for authentication.
    public func setManagementKey(
        _ managementKeyData: Data,
        type: PIVManagementKeyType,
        requiresTouch: Bool
    ) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        if requiresTouch {
            guard self.supports(PIVSessionFeature.usagePolicy) else { throw SessionError.notSupported }
        }
        if type == .tripleDES {
            guard self.supports(PIVSessionFeature.aesKey) else { throw SessionError.notSupported }
        }
        let tlv = TKBERTLVRecord(tag: tagSlotCardManagement, value: managementKeyData)
        var data = Data([type.rawValue])
        data.append(tlv.data)
        let apdu = APDU(cla: 0, ins: insSetManagementKey, p1: 0xff, p2: requiresTouch ? 0xfe : 0xff, command: data)
        try await send(apdu: apdu)
    }

    /// Authenticate with the Management Key.
    /// - Parameters:
    ///   - managementKey: The management key as Data.
    ///   - keyType: The management key type.
    public func authenticateWith(managementKey: Data, keyType: PIVManagementKeyType) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard keyType.keyLength == managementKey.count else { throw PIVSessionError.badKeyLength }

        let ccAlgorithm =
            switch keyType {
            case .tripleDES:
                UInt32(kCCAlgorithm3DES)
            case .AES128, .AES192, .AES256:
                UInt32(kCCAlgorithmAES)
            }

        let witness = TKBERTLVRecord(tag: tagAuthWitness, value: Data()).data
        let command = TKBERTLVRecord(tag: tagDynAuth, value: witness).data
        let witnessApdu = APDU(
            cla: 0,
            ins: insAuthenticate,
            p1: keyType.rawValue,
            p2: UInt8(tagSlotCardManagement),
            command: command,
            type: .extended
        )
        let witnessResult = try await send(apdu: witnessApdu)

        guard let dynAuthRecord = TKBERTLVRecord(from: witnessResult),
            dynAuthRecord.tag == tagDynAuth,
            let witnessRecord = TKBERTLVRecord(from: dynAuthRecord.value),
            witnessRecord.tag == tagAuthWitness
        else { throw PIVSessionError.responseDataNotTLVFormatted }
        let decryptedWitness = try witnessRecord.value.decrypt(
            algorithm: ccAlgorithm,
            key: managementKey
        )
        let decryptedWitnessRecord = TKBERTLVRecord(tag: tagAuthWitness, value: decryptedWitness)
        let challengeSent = Data.random(length: keyType.challengeLength)
        let challengeRecord = TKBERTLVRecord(tag: tagChallenge, value: challengeSent)
        var data = Data()
        data.append(decryptedWitnessRecord.data)
        data.append(challengeRecord.data)
        let authRecord = TKBERTLVRecord(tag: tagDynAuth, value: data)
        let challengeApdu = APDU(
            cla: 0,
            ins: insAuthenticate,
            p1: keyType.rawValue,
            p2: UInt8(tagSlotCardManagement),
            command: authRecord.data,
            type: .extended
        )
        let challengeResult = try await send(apdu: challengeApdu)

        guard let dynAuthRecord = TKBERTLVRecord(from: challengeResult),
            dynAuthRecord.tag == tagDynAuth,
            let encryptedChallengeRecord = TKBERTLVRecord(from: dynAuthRecord.value),
            encryptedChallengeRecord.tag == tagAuthResponse
        else { throw PIVSessionError.responseDataNotTLVFormatted }
        let challengeReturned = try encryptedChallengeRecord.value.decrypt(
            algorithm: ccAlgorithm,
            key: managementKey
        )
        guard challengeSent == challengeReturned else { throw PIVSessionError.authenticationFailed }
    }

    /// Reads metadata about the private key stored in a slot.
    /// - Parameter slot: The slot to read metadata about.
    /// - Returns: The metadata for the slot.
    public func getSlotMetadata(_ slot: PIVSlot) async throws -> PIVSlotMetadata {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard self.supports(PIVSessionFeature.metadata) else { throw SessionError.notSupported }
        let result = try await send(apdu: APDU(cla: 0, ins: insGetMetadata, p1: 0, p2: slot.rawValue))
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result) else { throw PIVSessionError.dataParseError }

        guard let rawKeyType = records.recordWithTag(tagMetadataAlgorithm)?.value.bytes[0],
            let keyType = PIVKeyType(rawValue: rawKeyType),
            let policyBytes = records.recordWithTag(tagMetadataPolicy)?.value.bytes, policyBytes.count > 1,
            let pinPolicy = PIVPinPolicy(rawValue: policyBytes[indexPinPolicy]),
            let touchPolicy = PIVTouchPolicy(rawValue: policyBytes[indexTouchPolicy]),
            let origin = records.recordWithTag(tagMetadataOrigin)?.value.uint8,
            let publicKeyData = records.recordWithTag(tagMetadataPublicKey)?.value,

            let publicKey = try? publicKey(from: publicKeyData, type: keyType)

        else { throw PIVSessionError.dataParseError }

        return PIVSlotMetadata(
            keyType: keyType,
            pinPolicy: pinPolicy,
            touchPolicy: touchPolicy,
            generated: origin == originGenerated,
            publicKey: publicKey
        )
    }

    /// Reads metadata about the card management key
    /// - Returns: The metadata for the management key.
    public func getManagementKeyMetadata() async throws -> PIVManagementKeyMetadata {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard self.supports(PIVSessionFeature.metadata) else { throw SessionError.notSupported }
        let apdu = APDU(cla: 0, ins: insGetMetadata, p1: 0, p2: p2SlotCardmanagement)
        let result = try await send(apdu: apdu)
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
            let isDefault = records.recordWithTag(tagMetadataIsDefault)?.value.bytes[0],
            let rawTouchPolicy = records.recordWithTag(tagMetadataPolicy)?.value.bytes[1],
            let touchPolicy = PIVTouchPolicy(rawValue: rawTouchPolicy)
        else { throw PIVSessionError.responseDataNotTLVFormatted }

        let keyType: PIVManagementKeyType
        if let rawKeyType = records.recordWithTag(tagMetadataAlgorithm)?.value.bytes[0] {
            guard let parsedKeyType = PIVManagementKeyType(rawValue: rawKeyType) else {
                throw PIVSessionError.unknownKeyType
            }
            keyType = parsedKeyType
        } else {
            keyType = .tripleDES
        }
        return PIVManagementKeyMetadata(isDefault: isDefault != 0, keyType: keyType, touchPolicy: touchPolicy)
    }

    /// Resets the PIV application to just-installed state.
    public func reset() async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        try await blockPin()
        try await blockPuk()
        let apdu = APDU(cla: 0, ins: insReset, p1: 0, p2: 0)
        try await send(apdu: apdu)
    }

    /// Get the serial number of the YubiKey.
    ///
    /// >Note: This requires the SERIAL_API_VISIBILE flag to be set on one of the YubiOTP slots (it is set by default).
    ///        This functionality requires support for feature serial, available on YubiKey 5 or later.
    ///
    /// - Returns: The serial number.
    public func getSerialNumber() async throws -> UInt32 {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard self.supports(PIVSessionFeature.serialNumber) else { throw SessionError.notSupported }
        let apdu = APDU(cla: 0, ins: insGetSerial, p1: 0, p2: 0)
        let result = try await send(apdu: apdu)
        return CFSwapInt32BigToHost(result.uint32)
    }

    /// Authenticate with pin.
    /// - Parameter pin: The UTF8 encoded pin. Default pin code is 123456.
    /// - Returns: Returns the number of retries left. If 0 pin authentication has been
    ///            blocked. Note that 15 is the higheset number of retries left that will be returned even if
    ///            remaining tries is higher.
    @discardableResult
    public func verifyPin(_ pin: String) async throws -> PIVVerifyPinResult {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard let pinData = pin.paddedPinData() else { throw PIVSessionError.invalidPin }
        let apdu = APDU(cla: 0, ins: insVerify, p1: 0, p2: 0x80, command: pinData)
        do {
            try await send(apdu: apdu)
            currentPinAttempts = maxPinAttempts
            return .success(currentPinAttempts)
        } catch {
            guard let responseError = error as? ResponseError  //,
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

    /// Set a new pin code for the YubiKey.
    /// - Parameters:
    ///   - newPin: The new UTF8 encoded pin.
    ///   - oldPin: Old pin code. UTF8 encoded.
    public func setPin(_ newPin: String, oldPin: String) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        try await _ = changeReference(ins: insChangeReference, p2: p2Pin, valueOne: oldPin, valueTwo: newPin)
    }

    /// Set a new puk code for the YubiKey.
    /// - Parameters:
    ///   - newPuk: The new UTF8 encoded puk.
    ///   - oldPuk: Old puk code. UTF8 encoded.
    public func setPuk(_ newPuk: String, oldPuk: String) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        try await _ = changeReference(ins: insChangeReference, p2: p2Puk, valueOne: oldPuk, valueTwo: newPuk)
    }

    /// Unblock a blocked pin code with the puk code.
    /// - Parameters:
    ///   - puk: The UTF8 encoded puk.
    ///   - newPin: The new UTF8 encoded pin.
    public func unblockPinWithPuk(_ puk: String, newPin: String) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        try await _ = changeReference(ins: insResetRetry, p2: p2Pin, valueOne: puk, valueTwo: newPin)
    }

    /// Reads metadata about the pin, such as total number of retries, attempts left, and if the pin has
    /// been changed from the default value.
    /// - Returns: The pin metadata.
    public func getPinMetadata() async throws -> PIVPinPukMetadata {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        return try await getPinPukMetadata(p2: p2Pin)
    }

    /// Reads metadata about the puk, such as total number of retries, attempts left, and if the puk has
    /// been changed from the default value.
    /// - Returns: The puk metadata.
    public func getPukMetadata() async throws -> PIVPinPukMetadata {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        return try await getPinPukMetadata(p2: p2Puk)
    }

    ///  Retrieve the number of pin attempts left for the YubiKey.
    ///
    /// >Note: If this command is run in a session where the correct pin has already been verified,
    ///        the correct value will not be retrievable, and the value returned may be incorrect if the
    ///        number of total attempts has been changed from the default.
    ///
    /// - Returns: Number of pin attempts left.
    public func getPinAttempts() async throws -> Int {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        if self.supports(PIVSessionFeature.metadata) {
            let metadata = try await getPinMetadata()
            return metadata.retriesRemaining
        } else {
            let apdu = APDU(cla: 0, ins: insVerify, p1: 0, p2: p2Pin)
            do {
                try await send(apdu: apdu)
                // Already verified, no way to know true count
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
    }

    /// Set the number of retries available for pin and puk entry.
    ///
    /// This method requires authentication and pin verification.
    ///
    /// - Parameters:
    ///   - pinAttempts: The number of attempts to allow for pin entry before blocking the pin.
    ///   - pukAttempts: The number of attempts to allow for puk entry before blocking the puk.
    public func set(pinAttempts: Int, pukAttempts: Int) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard let pinAttempts = UInt8(exactly: pinAttempts),
            let pukAttempts = UInt8(exactly: pukAttempts)
        else { throw PIVSessionError.invalidInput }
        let apdu = APDU(cla: 0, ins: insSetPinPukAttempts, p1: pinAttempts, p2: pukAttempts)
        try await send(apdu: apdu)
        maxPinAttempts = Int(pinAttempts)
        currentPinAttempts = Int(pinAttempts)
    }

    public func blockPin(counter: Int = 0) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
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
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        let retries = try await changeReference(ins: insResetRetry, p2: p2Pin, valueOne: "", valueTwo: "")
        if retries <= 0 || counter > 15 {
            return
        } else {
            try await blockPuk(counter: counter + 1)
        }
    }

    /// Reads metadata specific to YubiKey Bio multi-protocol.
    ///
    /// - Returns: Metadata about the key.
    public func getBioMetadata() async throws -> PIVBioMetadata {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        do {
            let apdu = APDU(cla: 0, ins: insGetMetadata, p1: 0, p2: UInt8(tagSlotOCCAuth))
            let data = try await send(apdu: apdu)
            let records = TKBERTLVRecord.sequenceOfRecords(from: data)
            guard let isConfigured = records?.recordWithTag(tagMetadataBioConfigured)?.value.integer,
                let retries = records?.recordWithTag(tagMetadataRetries)?.value.integer,
                let temporaryPin = records?.recordWithTag(tagMetadataTemporaryPIN)?.value.integer
            else { throw PIVSessionError.dataParseError }
            return PIVBioMetadata(
                isConfigured: isConfigured == 1,
                attemptsRemaining: retries,
                temporaryPin: temporaryPin == 1
            )
        } catch {
            if let responseError = error as? ResponseError,
                responseError.responseStatus.status == .referencedDataNotFound
            {
                throw SessionError.notSupported
            } else {
                throw error
            }
        }
    }

    /// Authenticate with YubiKey Bio multi-protocol capabilities.
    ///
    /// >Note: Before calling this method, clients must verify that the authenticator is bio-capable and
    ///        not blocked for bio matching.
    /// - Parameters:
    ///   - requestTemporaryPin: After successful match generate a temporary PIN.
    ///   - checkOnly: Check verification state of biometrics, don't perform UV.
    /// - Returns: Temporary pin if requestTemporaryPin is true, otherwise null.
    public func verifyUv(requestTemporaryPin: Bool, checkOnly: Bool) async throws -> Data? {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        if requestTemporaryPin && checkOnly {
            throw SessionError.illegalArgument
        }
        do {
            var data: Data? = nil
            if !checkOnly {
                if requestTemporaryPin {
                    data = TKBERTLVRecord(tag: 0x02, value: Data()).data
                } else {
                    data = TKBERTLVRecord(tag: 0x03, value: Data()).data
                }
            }
            let apdu = APDU(cla: 0, ins: insVerify, p1: 0, p2: UInt8(tagSlotOCCAuth), command: data)
            let response = try await send(apdu: apdu)
            return requestTemporaryPin ? response : nil
        } catch {
            guard let responseError = error as? ResponseError else { throw error }
            guard responseError.responseStatus.status != .referencedDataNotFound else {
                throw SessionError.notSupported
            }
            let retries = retriesFrom(responseError: responseError)
            if retries >= 0 {
                throw SessionError.invalidPin(retries)
            } else {
                // Status code returned error, not number of retries
                throw error
            }
        }
    }

    /// Authenticate YubiKey Bio multi-protocol with temporary PIN.
    ///
    /// The PIN has to be generated by calling ``verifyUv(requestTemporaryPin:checkOnly:)`` and is
    /// valid only for operations during this session and depending on slot {@link PinPolicy}.
    ///
    /// >Note: Before calling this method, clients must verify that the authenticator is bio-capable and
    ///        not blocked for bio matching.
    ///
    /// - Parameter pin: Temporary pin.
    public func verifyTemporaryPin(_ pin: Data) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        guard pin.count == temporaryPinLength else { throw SessionError.illegalArgument }
        do {
            let data = TKBERTLVRecord(tag: 0x01, value: pin).data
            let apdu = APDU(cla: 0, ins: insVerify, p1: 0, p2: UInt8(tagSlotOCCAuth), command: data)
            try await send(apdu: apdu)
            return
        } catch {
            guard let responseError = error as? ResponseError else { throw error }
            guard responseError.responseStatus.status != .referencedDataNotFound else {
                throw SessionError.notSupported
            }
            throw error
        }
    }
}

extension PIVSession {

    private func usePrivateKeyInSlot(
        slot: PIVSlot,
        keyType: PIVKeyType,
        message: Data,
        exponentiation: Bool
    ) async throws -> Data {
        Logger.piv.debug(
            "\(String(describing: self).lastComponent), \(#function): slot: \(String(describing: slot)), type: \(String(describing: keyType)), message: \(message.hexEncodedString), exponentiation: \(exponentiation)"
        )
        var recordsData = Data()
        recordsData.append(TKBERTLVRecord(tag: tagAuthResponse, value: Data()).data)
        recordsData.append(TKBERTLVRecord(tag: exponentiation ? tagExponentiation : tagChallenge, value: message).data)
        let command = TKBERTLVRecord(tag: tagDynAuth, value: recordsData).data
        let apdu = APDU(
            cla: 0,
            ins: insAuthenticate,
            p1: keyType.rawValue,
            p2: slot.rawValue,
            command: command,
            type: .extended
        )
        let resultData = try await send(apdu: apdu)
        guard let result = TKBERTLVRecord.init(from: resultData), result.tag == tagDynAuth else {
            throw PIVSessionError.responseDataNotTLVFormatted
        }
        guard let data = TKBERTLVRecord(from: result.value), data.tag == tagAuthResponse else {
            throw PIVSessionError.responseDataNotTLVFormatted
        }
        return data.value
    }

    private func putObject(_ data: Data, objectId: Data) async throws {
        var command = Data()
        command.append(TKBERTLVRecord(tag: tagObjectId, value: objectId).data)
        command.append(TKBERTLVRecord(tag: tagObjectData, value: data).data)
        let apdu = APDU(cla: 0, ins: insPutData, p1: 0x3f, p2: 0xff, command: command, type: .extended)
        try await send(apdu: apdu)
    }

    private func changeReference(ins: UInt8, p2: UInt8, valueOne: String, valueTwo: String) async throws -> Int {
        guard let paddedValueOne = valueOne.paddedPinData(), let paddedValueTwo = valueTwo.paddedPinData() else {
            throw PIVSessionError.invalidPin
        }
        let data = paddedValueOne + paddedValueTwo
        let apdu = APDU(cla: 0, ins: ins, p1: 0, p2: p2, command: data)
        do {
            try await send(apdu: apdu)
            return currentPinAttempts
        } catch {
            guard let responseError = error as? ResponseError else { throw PIVSessionError.invalidResponse }
            let retries = retriesFrom(responseError: responseError)
            if retries >= 0 {
                if p2 == 0x80 {
                    currentPinAttempts = retries
                }
            }
            return retries
        }
    }

    private func checkKeyFeatures(
        keyType: PIVKeyType,
        pinPolicy: PIVPinPolicy,
        touchPolicy: PIVTouchPolicy,
        generateKey: Bool
    ) async throws {
        Logger.piv.debug("\(String(describing: self).lastComponent), \(#function)")
        if keyType == .ecc(.p384) {
            guard self.supports(PIVSessionFeature.p384) else { throw SessionError.notSupported }
        }
        if pinPolicy != .`defaultPolicy` || touchPolicy != .`defaultPolicy` {
            guard self.supports(PIVSessionFeature.usagePolicy) else { throw SessionError.notSupported }
        }
        if pinPolicy == .matchAlways || pinPolicy == .matchOnce {
            // This will throw SessionError.notSupported if the key is not a Bio key
            _ = try await self.getBioMetadata()
        }
        if generateKey && (keyType == .rsa(.bits1024) || keyType == .rsa(.bits2048)) {
            guard self.supports(PIVSessionFeature.rsaGeneration) else { throw SessionError.notSupported }
        }
        if generateKey && (keyType == .rsa(.bits3072) || keyType == .rsa(.bits4096)) {
            guard self.supports(PIVSessionFeature.rsa3072and4096) else { throw SessionError.notSupported }
        }
        if keyType == .ed25519 {
            guard self.supports(PIVSessionFeature.ed25519) else { throw SessionError.notSupported }
        }
        if keyType == .x25519 {
            guard self.supports(PIVSessionFeature.x25519) else { throw SessionError.notSupported }
        }
    }

    private func getPinPukMetadata(p2: UInt8) async throws -> PIVPinPukMetadata {
        guard self.supports(PIVSessionFeature.metadata) else { throw SessionError.notSupported }
        let apdu = APDU(cla: 0, ins: insGetMetadata, p1: 0, p2: p2)
        let result = try await send(apdu: apdu)
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: result),
            let isDefault = records.recordWithTag(tagMetadataIsDefault)?.value.bytes[0],
            let retriesTotal = records.recordWithTag(tagMetadataRetries)?.value.bytes[0],
            let retriesRemaining = records.recordWithTag(tagMetadataRetries)?.value.bytes[1]
        else { throw PIVSessionError.responseDataNotTLVFormatted }

        return PIVPinPukMetadata(
            isDefault: isDefault != 0,
            retriesTotal: Int(retriesTotal),
            retriesRemaining: Int(retriesRemaining)
        )
    }

    private func retriesFrom(responseError: ResponseError) -> Int {
        let statusCode = responseError.responseStatus.rawStatus
        if statusCode == 0x6983 {
            return 0
        } else if self.version < Version(withString: "1.0.4")! {
            if statusCode >= 0x6300 && statusCode <= 0x63ff {
                return Int(statusCode & 0xff)
            }
        } else {
            if statusCode >= 0x63c0 && statusCode <= 0x63cf {
                return Int(statusCode & 0xf)
            }
        }
        return -1
    }

    @discardableResult
    private func send(apdu: APDU) async throws -> Data {
        if let processor {
            return try await processor.send(apdu: apdu, using: connection)
        } else {
            return try await connection.send(apdu: apdu)
        }
    }
}

extension ResponseStatus {
    fileprivate func pinRetriesLeft(version: Version) -> Int? {
        if self.rawStatus == 0x6983 {
            return 0
        }
        if version < Version(withString: "1.0.4")! {
            if self.rawStatus >= 0x6300 && self.rawStatus <= 0x63ff {
                return Int(self.rawStatus & 0xff)
            }
        } else {
            if self.rawStatus >= 0x63c0 && self.rawStatus <= 0x63cf {
                return Int(self.rawStatus & 0xf)
            }
        }
        return nil
    }
}

extension String {
    fileprivate func paddedPinData() -> Data? {
        guard var data = self.data(using: .utf8) else { return nil }
        let paddingSize = 8 - data.count
        for _ in 0..<paddingSize {
            data.append(0xff)
        }
        return data
    }
}

// Special slot for the management key
private let tagSlotCardManagement: TKTLVTag = 0x9b
private let tagSlotOCCAuth: TKTLVTag = 0x96

// Instructions
private let insAuthenticate: UInt8 = 0x87
private let insVerify: UInt8 = 0x20
private let insReset: UInt8 = 0xfb
private let insGetVersion: UInt8 = 0xfd
private let insGetSerial: UInt8 = 0xf8
private let insGetMetadata: UInt8 = 0xf7
private let insGetData: UInt8 = 0xcb
private let insPutData: UInt8 = 0xdb
private let insMoveKey: UInt8 = 0xf6
private let insImportKey: UInt8 = 0xfe
private let insChangeReference: UInt8 = 0x24
private let insResetRetry: UInt8 = 0x2c
private let insSetManagementKey: UInt8 = 0xff
private let insSetPinPukAttempts: UInt8 = 0xfa
private let insGenerateAsymetric: UInt8 = 0x47
private let insAttest: UInt8 = 0xf9

// Tags
private let tagDynAuth: TKTLVTag = 0x7c
private let tagAuthWitness: TKTLVTag = 0x80
private let tagChallenge: TKTLVTag = 0x81
private let tagExponentiation: TKTLVTag = 0x85
private let tagAuthResponse: TKTLVTag = 0x82
private let tagGenAlgorithm: TKTLVTag = 0x80
private let tagObjectData: TKTLVTag = 0x53
private let tagObjectId: TKTLVTag = 0x5c
private let tagCertificate: TKTLVTag = 0x70
private let tagCertificateInfo: TKTLVTag = 0x71
private let tagLRC: TKTLVTag = 0xfe
private let tagPinPolicy: TKTLVTag = 0xaa
private let tagTouchpolicy: TKTLVTag = 0xab

// Metadata tags
private let tagMetadataAlgorithm: TKTLVTag = 0x01
private let tagMetadataOrigin: TKTLVTag = 0x03
private let tagMetadataPublicKey: TKTLVTag = 0x04
private let tagMetadataIsDefault: TKTLVTag = 0x05
private let tagMetadataRetries: TKTLVTag = 0x06
private let tagMetadataPolicy: TKTLVTag = 0x02

private let originGenerated: UInt8 = 1
private let originImported: UInt8 = 2

private let indexPinPolicy: Int = 0
private let indexTouchPolicy: Int = 1
private let indexRetriesTotal: Int = 0
private let indexRetriesRemaining: Int = 1

private let tagMetadataBioConfigured: TKTLVTag = 0x07
private let tagMetadataTemporaryPIN: TKTLVTag = 0x08

private let p2Pin: UInt8 = 0x80
private let p2Puk: UInt8 = 0x81
private let p2SlotCardmanagement: UInt8 = 0x9b

private let temporaryPinLength: Int = 16
