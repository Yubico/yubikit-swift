import Foundation
import CryptoTokenKit
import CommonCrypto
import OSLog


public final actor SecurityDomainSession: Session {
    
    private let connection: Connection
    private let processor: SCPProcessor?

    private init(connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws {
        try await connection.selectApplication(.securityDomain)
        self.connection = connection
        if let scpKeyParams {
            processor = try await SCPProcessor(connection: connection, keyParams: scpKeyParams)
        } else {
            processor = nil
        }
    }
    
    public static func session(withConnection connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws -> SecurityDomainSession {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        return try await SecurityDomainSession(connection: connection, scpKeyParams: scpKeyParams)
    }
    
    nonisolated public func supports(_ feature: SessionFeature) -> Bool {
        return true
    }
    
    public func getData(tag: UInt16, data: Data?) async throws -> Data {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        return try await send(apdu: APDU(cla: 0x00, ins: 0xCA, p1: UInt8(tag >> 8) , p2: UInt8(tag & 0xff), command: data))
    }
    
    public func storeData(_ data: Data) async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        try await send(apdu: APDU(cla: 0x00, ins: 0xE2, p1: 0x90, p2: 0x00, command: data))
    }
    
    public func getCardRecognitionData() async throws -> Data {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        let data = try await self.getData(tag: 0x66, data: nil)
        guard let tlv = TKBERTLVRecord(from: data), tlv.tag == 0x73 else { throw SessionError.unexpectedResponse }
        return tlv.value
    }
    
    public func getKeyInformation() async throws -> [SCPKeyRef: [UInt8: UInt8]] {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        
        let tlvData: Data = try await self.getData(tag: 0xE0, data: nil)
        guard let tlvs = TKBERTLVRecord.sequenceOfRecords(from: tlvData) else {
            throw SessionError.unexpectedResponse
        }
        var keys = [SCPKeyRef: [UInt8: UInt8]]()
        try tlvs.forEach { tlv in
            if tlv.tag == 0xC0 {
                var data = tlv.value
                guard let kid = data.extract(1)?.uint8, let kvn = data.extract(1)?.uint8 else {
                    throw SessionError.unexpectedResponse
                }
                let keyRef = SCPKeyRef(kid: kid, kvn: kvn)
                var components: [UInt8: UInt8] = [:]
                while data.count >= 2 {
                    guard let typeByte = data.extract(1)?.uint8, let versionByte = data.extract(1)?.uint8 else {
                        throw SessionError.unexpectedResponse
                    }
                    components[typeByte] = versionByte
                }
                keys[keyRef] = components
            }
        }
        return keys
    }
    
    public func getCertificateBundle(scpKeyRef: SCPKeyRef) async throws -> [SecCertificate] {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        do {
            let result = try await getData(tag: 0xBF21, data: TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: scpKeyRef.data).data).data)
            guard let rawCerts = TKBERTLVRecord.sequenceOfRecords(from: result) else { fatalError() }
            let certs = rawCerts.map { SecCertificateCreateWithData(nil, $0.data as CFData) }.compactMap { $0 }
            guard certs.count == rawCerts.count else { fatalError() }
            return certs
        } catch {
            if let reponseError = error as? ResponseError, reponseError.responseStatus.status == .referencedDataNotFound {
                return []
            } else {
                throw error
            }
        }
    }
    
    public func getSupportedCaIdentifiers(kloc: Bool, klcc: Bool) async throws -> [SCPKeyRef: Data] {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        if !kloc && !klcc {
            throw SessionError.illegalArgument
        }
        var data = Data()
        if kloc {
            do {
                data.append(try await getData(tag: 0xFF33, data: nil))
            } catch {
                if let responseError = error as? ResponseError, responseError.responseStatus.status != .referencedDataNotFound {
                    throw error
                }
            }
        }
        if klcc {
            do {
                data.append(try await getData(tag: 0xFF34, data: nil))
            } catch {
                if let responseError = error as? ResponseError, responseError.responseStatus.status != .referencedDataNotFound {
                    throw error
                }
            }
        }
        guard let tlvs =  TKBERTLVRecord.sequenceOfRecords(from: data) else { throw SessionError.unexpectedResponse }
        var identifiers = [SCPKeyRef: Data]()
        for i in stride(from: 0, to: tlvs.count, by: 2) {
            var ref = tlvs[i + 1].value
            guard let kid = ref.extract(1)?.uint8, let kvn = ref.extract(1)?.uint8 else {
                throw SessionError.unexpectedResponse
            }
            let keyRef = SCPKeyRef(kid: kid, kvn: kvn)
            identifiers[keyRef] = tlvs[i].value
        }
        return identifiers
    }
    
    /// Store the certificate chain for a given key.
    ///
    /// Requires off-card entity verification.
    /// Certificates should be in order, with the leaf certificate last.
    /// - Parameter keyRef: a reference to the key for which to store the certificates
    /// - Parameter certificates: the certificates to store
    public func storeCertificateBundle(keyRef: SCPKeyRef, certificiates: [SecCertificate]) async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        var certsData = Data()
        certificiates.forEach { certificate in
            let certData = SecCertificateCopyData(certificate) as Data
            certsData.append(certData)
        }
        let data = TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data +
        TKBERTLVRecord(tag: 0xBF21, value: certsData).data
        try await storeData(data)
    }
    
    
    /// Store which certificate serial numbers that can be used for a given key.
    ///
    /// Requires off-card entity verification.
    /// If no allowlist is stored, any certificate signed by the CA can be used.
    /// - Parameter keyRef: a reference to the key for which to store the allowlist
    /// - Parameter serials: the list of serial numbers to store
    public func storeAllowlist(keyRef: SCPKeyRef, serials: [Data]) async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        
        var serialsData = Data()
        serials.forEach { serial in
            serialsData.append(TKBERTLVRecord(tag: 0x93, value: serial).data)
        }
        let data = TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data + TKBERTLVRecord(tag: 0x70, value: serialsData).data
        try await storeData(data)
    }
    
    /// Store the SKI (Subject Key Identifier) for the CA of a given key.
    /// Requires off-card entity verification.
    /// - Parameter keyRef: a reference to the key for which to store the CA issuer
    /// - Parameter ski: the Subject Key Identifier to store
    public func storeCaIssuer(keyRef: SCPKeyRef, ski: Data) async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        let klcc: UInt8
        switch keyRef.kid {
        case SCPKid.scp11a.rawValue, SCPKid.scp11b.rawValue, SCPKid.scp11c.rawValue: klcc = 1
        default: klcc = 0
        }
        let data = TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x80, value: klcc.data).data +
                                  TKBERTLVRecord(tag: 0x42, value: ski).data +
                                  TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data
        try await storeData(data)
    }
    
    /// Delete one (or more) keys.
    ///
    /// Requires off-card entity verification.
    /// All keys matching the given KID and/or KVN will be deleted (0 is treated as a wildcard).
    /// To delete the final key you must set deleteLast = true.
    /// - Parameter keyRef: a reference to the key to delete
    /// - Parameter deleteLast: must be true if deleting the final key, false otherwise
    public func deleteKey(keyRef: SCPKeyRef, deleteLast: Bool = false) async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        var kid = keyRef.kid
        let kvn = keyRef.kvn

        if kid == 0 && kvn == 0 {
            throw SessionError.illegalArgument
        }

        if kid == 1 || kid == 2 || kid == 3 {
            if kvn != 0 {
                kid = 0
            } else {
                throw SessionError.illegalArgument
            }
        }
        
        var data = Data()
        if kid != 0 {
            data.append(TKSimpleTLVRecord(tag: 0xD0, value: kid.data).data)
        }
        if kvn != 0 {
            data.append(TKSimpleTLVRecord(tag: 0xD2, value: kvn.data).data)
        }

        let apdu = APDU(cla: 0x80, ins: 0xE4, p1: 0, p2: deleteLast ? 1 : 0, command: data)
        print(apdu)
        try await send(apdu: apdu)
    }

    /// Generate a new SCP11 key.
    ///
    /// Requires off-card entity verification.
    /// - Parameter keyRef: the KID-KVN pair to assign the new key
    /// - Parameter replaceKvn: 0 to generate a new keypair, non-zero to replace an existing KVN
    /// - Returns: the public key from the generated key pair
    public func generateEcKey(keyRef: SCPKeyRef, replaceKvn: UInt8) async throws -> SecKey {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        
        let params = TKBERTLVRecord(tag: 0xF0, value: Data()).data
        var data = Data()
        data.append(keyRef.kvn.data)
        data.append(contentsOf: params)

        let apdu = APDU(cla: 0x80, ins: 0xF1, p1: replaceKvn, p2: keyRef.kid, command: data)

        let response = try await send(apdu: apdu)
        
        guard let tlv = TKBERTLVRecord(from: response), tlv.tag == 0xB0 else {
            throw SessionError.unexpectedResponse
        }
        
        var error: Unmanaged<CFError>?
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                         kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
        guard let key = SecKeyCreateWithData(tlv.value as CFData, attributes, &error) else { throw error!.takeRetainedValue() as Error }
        return key
    }
    
    /// Imports an SCP03 key set.
    /// Requires off-card entity verification.
    /// - Parameter keyRef: the KID-KVN pair to assign the new key set, KID must be 1
    /// - Parameter keys: the key material to import
    /// - Parameter replaceKvn: 0 to generate a new keypair, non-zero to replace an existing KVN
    public func putKey(keyRef: SCPKeyRef, keys: StaticKeys, replaceKvn: UInt8) async throws {
        guard keyRef.kid == SCPKid.scp03.rawValue else {
            throw SessionError.illegalArgument("KID must be 0x01 for SCP03 key sets")
        }
        guard let dek = keys.dek else {
            throw SessionError.illegalArgument("New DEK must be set in static keys")
        }
        guard let processor else {
            throw SessionError.notSupported("No session DEK key available")
        }

        var data = Data([keyRef.kvn])
        var expected = Data([keyRef.kvn])

        let defaultKcvIv: Data = .init(repeating: 0x01, count: 16)

        for key in [keys.enc, keys.mac, dek] {
            let kcv = SCPState.cbcEncrypt(key: key, data: defaultKcvIv)!.prefix(3)

            let currentDek = processor.state.sessionKeys.dek!

            let encryptedKey = SCPState.cbcEncrypt(key: currentDek, data: key)
            data.append(TKSimpleTLVRecord(tag: 0x88, value: encryptedKey!).data)
            data.append(UInt8(kcv.count))
            data.append(kcv)
            expected.append(kcv)
        }

        assert(data.bytes.count == 1 + 3 * (18 + 4), "Unexpected command data length")

        let apdu = APDU(cla: 0x80, ins: 0xD8, p1: replaceKvn, p2: 0x80 | keyRef.kid, command: data)
        let resp = try await send(apdu: apdu)
        
        guard resp.constantTimeCompare(expected) else {
            throw SessionError.unexpectedResult
        }
        Logger.securityDomain.info("SCP03 Key set imported")
    }
    
    /// Imports a secret key for SCP11.
    /// Requires off-card entity verification.
    /// - Parameter keyRef: the KID-KVN pair to assign the new secret key, KID must be 0x11, 0x13, or 0x15
    /// - Parameter secretKey: a private EC key used to authenticate the SD
    /// - Parameter replaceKvn: 0 to generate a new keypair, non-zero to replace an existing KVN
    public func putKey(keyRef: SCPKeyRef, privateKey: SecKey, replaceKvn: UInt8) async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        guard privateKey.isSECP256R1Key() else {
            throw SessionError.illegalArgument // Expected SECP256R1 private key size
        }

        guard let processor else {
            throw SessionError.notSupported
        }

        var data = Data()
        data.append(keyRef.kvn)
        let expected = Data([keyRef.kvn])

        
        var error: Unmanaged<CFError>?
        guard let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            throw error?.takeRetainedValue() ?? SessionError.illegalArgument
        }
        
        let encryptedKey = try processor.state.encrypt(privateKeyData)
        data.append(TKBERTLVRecord(tag: 0xB1, value: encryptedKey).data)
        data.append(TKBERTLVRecord(tag: 0xF0, value: Data([0x00])).data)
        data.append(0x00)

        let apdu = APDU(cla: 0x80, ins: 0xD8, p1: replaceKvn, p2: keyRef.kid, command: data)
        let resp = try await send(apdu: apdu)
        guard resp.constantTimeCompare(expected) else {
            throw SessionError.unexpectedResult
        }
        Logger.securityDomain.info("SCP11 private key imported")
    }
    
    /// Imports a public key for authentication of the off-card entity for SCP11a/c.
    /// Requires off-card entity verification.
    /// - Parameter keyRef: the KID-KVN pair to assign the new public key
    /// - Parameter publicKey: a public EC key used as CA to authenticate the off-card entity
    /// - Parameter replaceKvn: 0 to generate a new keypair, non-zero to replace an existing KVN
    public func putKey(keyRef: SCPKeyRef, publicKey: SecKey, replaceKvn: UInt8) async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        guard publicKey.isSECP256R1Key() else {
            throw SessionError.illegalArgument
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error?.takeRetainedValue() ?? SessionError.illegalArgument
        }

        var data = Data()
        data.append(keyRef.kvn)
        let expected = Data([keyRef.kvn])

        data.append(TKBERTLVRecord(tag: 0xB0, value: publicKeyData).data)
        data.append(TKBERTLVRecord(tag: 0xF0, value: Data([0x00])).data)
        data.append(0x00)

        let apdu = APDU(cla: 0x80, ins: 0xD8, p1: replaceKvn, p2: keyRef.kid, command: data)
        let resp = try await send(apdu: apdu)
        guard resp.constantTimeCompare(expected) else {
            throw SessionError.unexpectedResult
        }

        Logger.securityDomain.debug("SCP11 public key imported")
    }
    
    /// Perform a factory reset of the Security Domain.
    /// This will remove all keys and associated data, as well as restore the default SCP03 static keys,
    /// and generate a new (attestable) SCP11b key.
    public func reset() async throws {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")

        let data = Data(repeating: 0x00, count: 8)
        let keyInfo = try await getKeyInformation()

        for (keyRefInitial, _) in keyInfo {
            var keyRef = keyRefInitial
            let ins: UInt8

            switch keyRef.kid {
            case SCPKid.scp03.rawValue:
                keyRef = SCPKeyRef(kid: 0, kvn: 0)
                ins = 0x50
            case 0x02, 0x03:
                continue  // Skip these as they are deleted by 0x01
            case SCPKid.scp11a.rawValue, SCPKid.scp11c.rawValue:
                ins = 0x82
            case SCPKid.scp11b.rawValue:
                ins = 0x88
            default: // 0x10, 0x20-0x2F
                ins = 0x2A
            }
            
            let apdu = APDU(cla: 0x80, ins: ins, p1: keyRef.kvn, p2: keyRef.kid, command: data)
            
            for _ in 0..<65 {
                do {
                    _ = try await send(apdu: apdu)
                } catch let error as ResponseError {
                    let shouldExit = switch error.responseStatus.status {
                    case .authMethodBlocked, .securityConditionNotSatisfied:
                        true
                    case .incorrectParameters:
                        false
                    default:
                        throw error
                    }
                    if shouldExit {
                        break // This breaks out of the for loop
                    } else {
                        continue
                    }
                }
            }
        }
        Logger.securityDomain.debug("SCP keys reset")
    }
    
    deinit {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
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


extension SecKey {
    func isSECP256R1Key() -> Bool {
        guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any] else {
            return false
        }
        guard let keyType = attributes[kSecAttrKeyType] as? String, let keySize = attributes[kSecAttrKeySizeInBits] as? Int else {
            return false
        }
        return keyType == kSecAttrKeyTypeECSECPrimeRandom as String && keySize == 256
    }
    
}
