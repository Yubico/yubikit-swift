import Foundation
import CryptoTokenKit
import OSLog


public final actor SecurityDomainSession: Session, InternalSession {
    
    private var _connection: Connection?
    internal func connection() async -> Connection? {
        return _connection
    }
    internal func setConnection(_ connection: Connection?) async {
        _connection = connection
    }

    private init(connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws {
        let result = try await connection.selectApplication(.securityDomain)
        self._connection = connection
        let internalConnection = await self.internalConnection()
        if let scpKeyParams {
            let processor = try await SCPProcessor(connection: connection, keyParams: scpKeyParams)
            await internalConnection?.setProcessor(processor)
        }
        await internalConnection?.setSession(self)
    }
    
    public static func session(withConnection connection: Connection, scpKeyParams: SCPKeyParams? = nil) async throws -> SecurityDomainSession {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        let internalConnection = connection as? InternalConnection
        let currentSession = await internalConnection?.session()
        await currentSession?.end()
        let session = try await SecurityDomainSession(connection: connection, scpKeyParams: scpKeyParams)
        return session
    }
    
    public func end() async {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
        let internalConnection = await internalConnection()
        await internalConnection?.setSession(nil)
        await setConnection(nil)
    }
    
    nonisolated public func supports(_ feature: SessionFeature) -> Bool {
        return true
    }
    
    public func getData(tag: UInt16, data: Data?) async throws -> Data {
        guard let connection = _connection else { throw SessionError.noConnection }
        return try await connection.send(apdu: APDU(cla: 0x00, ins: 0xCA, p1: UInt8(tag >> 8) , p2: UInt8(tag & 0xff), command: data))
    }
    
    public func storeData(_ data: Data) async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        try await connection.send(apdu: APDU(cla: 0x00, ins: 0xE2, p1: 0x90, p2: 0x00, command: data))
    }
    
    public func getCardRecognitionData() async throws -> Data {
        let data = try await self.getData(tag: 0x66, data: nil)
        guard let tlv = TKBERTLVRecord(from: data), tlv.tag == 0x73 else { throw SessionError.unexpectedResponse }
        return tlv.value
    }
    
    public func getKeyInformation() async throws -> [SCPKeyRef: [UInt8: UInt8]] {
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
        keys.forEach { (key: SCPKeyRef, value: [UInt8 : UInt8]) in
            print("\(key): \(value)")
        }
        print(keys)
        return keys
    }
    
    public func getCertificateBundle(scpKeyRef: SCPKeyRef) async throws -> [SecCertificate] {
        do {
            let result = try await getData(tag: 0xBF21, data: TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: scpKeyRef.data).data).data)
            print("getCertificateBundle: \(result.hexEncodedString)")
            guard let rawCerts = TKBERTLVRecord.sequenceOfRecords(from: result) else { fatalError() }
            
            rawCerts.forEach { record in
                print("certData: \(record.data.hexEncodedString)")
            }
            
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
    
    public func storeCertificateBundle(keyRef: SCPKeyRef, certificiates: [SecCertificate]) async throws {
        var certsData = Data()
        certificiates.forEach { certificate in
            let certData = SecCertificateCopyData(certificate) as Data
            certsData.append(certData)
        }
        let data = TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data +
        TKBERTLVRecord(tag: 0xBF21, value: certsData).data
        try await storeData(data)
    }
    
    public func storeAllowlist(keyRef: SCPKeyRef, serials: [Data]) async throws {
        var serialsData = Data()
        serials.forEach { serial in
            serialsData.append(TKBERTLVRecord(tag: 0x93, value: serial).data)
        }
        var data = TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data + TKBERTLVRecord(tag: 0x70, value: serialsData).data
        try await storeData(data)
    }
    
    public func storeCaIssuer(keyRef: SCPKeyRef, ski: Data) async throws {
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
    
    public func deleteKey(keyRef: SCPKeyRef, deleteLast: Bool = false) async throws {
        guard let connection = _connection else { throw SessionError.noConnection }
        
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
            data.append(TKBERTLVRecord(tag: 0xD0, value: kid.data).data)
        }
        if kvn != 0 {
            data.append(TKBERTLVRecord(tag: 0xD2, value: kvn.data).data)
        }

        let apdu = APDU(cla: 0x80, ins: 0xE4, p1: 0, p2: deleteLast ? 1 : 0, command: data)
        try await connection.send(apdu: apdu)
    }

    public func generateEcKey(keyRef: SCPKeyRef, replaceKvn: UInt8) async throws -> SecKey {
        let params = TKBERTLVRecord(tag: 0xF0, value: Data()).data
        var data = Data()
        data.append(keyRef.kvn.data)
        data.append(contentsOf: params)

        let apdu = APDU(cla: 0x80, ins: 0xF1, p1: replaceKvn, p2: keyRef.kid, command: data)

        guard let connection = _connection else { throw SessionError.noConnection }
        let response = try await connection.send(apdu: apdu)
        
        guard let tlv = TKBERTLVRecord(from: response), tlv.tag == 0xB0 else {
            throw SessionError.unexpectedResponse
        }
        
        var error: Unmanaged<CFError>?
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeEC,
                         kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
        guard let key = SecKeyCreateWithData(tlv.value as CFData, attributes, &error) else { throw error!.takeRetainedValue() as Error }
        return key
    }
    
    public func putKey(keyRef: SCPKeyRef, keys: StaticKeys, replaceKvn: UInt8) async throws {
        guard keyRef.kid == SCPKid.scp03.rawValue else {
            throw SessionError.illegalArgument
        }
        guard let dek = keys.dek else {
            throw SessionError.illegalArgument
        }
        guard let dataEncryptor = await (try? internalConnection()?.processor()?.dataEncryptor()) else {
            throw SessionError.illegalArgument
        }

        var data = Data([keyRef.kvn])
        var expected = Data([keyRef.kvn])

        for key in [keys.enc, keys.mac, dek] {
            guard let secret = key else { throw SessionError.illegalArgument }
            let keyBytes = secret.withUnsafeBytes { Data($0) }
            let encryptedKey = try dataEncryptor.encrypt(data: keyBytes)
            let kcvFull = try SCPState.cbcEncrypt(key: secret, iv: SCPState.defaultKcvIv)
            let kcv = kcvFull.prefix(3)
            var tlv = TKBERTLVRecord(tag: 0x80, value: encryptedKey).data
            tlv.append(UInt8(kcv.count))
            tlv.append(contentsOf: kcv)
            data.append(tlv)
            expected.append(contentsOf: kcv)
        }

        guard let connection = _connection else { throw SessionError.noConnection }
        let apdu = APDU(cla: 0x80, ins: 0xD8, p1: replaceKvn, p2: 0x80 | keyRef.kid, command: data)
        let resp = try await connection.send(apdu: apdu)
        guard resp == expected else {
            throw SessionError.invalidKeyCheckValue
        }

        Logger.securityDomain.info("SCP03 Key set imported")
    }
    
    deinit {
        Logger.securityDomain.debug("\(String(describing: self).lastComponent), \(#function)")
    }
}
