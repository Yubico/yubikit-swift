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

/// Session for the YubiKey **Security Domain** application.
///
/// Provides async, high‑level helpers for key management, cert storage and
/// factory reset.
///
/// Create with ``makeSession(connection:scpKeyParams:)`` and call the instance
/// methods as needed.
public final actor SecurityDomainSession: SmartCardSessionInternal, HasSecurityDomainLogger {
    public static let application: Application = .securityDomain

    public typealias Feature = SecurityDomainFeature
    public typealias Error = SCPError

    let interface: SmartCardInterface<Error>

    private init(connection: SmartCardConnection, scpKeyParams: SCPKeyParams? = nil) async throws(SCPError) {
        // Create interface with application selection and optional SCP
        let interface = try await SmartCardInterface<Error>(
            connection: connection,
            application: .securityDomain,
            keyParams: scpKeyParams
        )

        self.interface = interface
    }

    /// Creates a new ``SecurityDomainSession`` by selecting the Security Domain application on the provided
    /// connection.
    ///
    /// - Parameters:
    ///   - connection: The smart‑card connection that will be used for all APDU exchanges.
    ///   - scpKeyParams: Optional SCP11 key‐establishment parameters. Pass `nil` for unauthenticated access.
    ///
    /// - Throws: ``SCPError`` if the application selection fails or if the SCP11 processor cannot be created.
    /// - Returns: A fully initialised ``SecurityDomainSession`` ready for commands.
    // @TraceScope
    public static func makeSession(
        connection: SmartCardConnection,
        scpKeyParams: SCPKeyParams? = nil
    ) async throws(SCPError) -> SecurityDomainSession {
        try await SecurityDomainSession(connection: connection, scpKeyParams: scpKeyParams)
    }

    /// Checks if the session supports the specified feature.
    ///
    /// This method is required by the Session protocol but is unreachable for
    /// SecurityDomainSession since SecurityDomainFeature is an empty enum with no cases.
    /// No instances of SecurityDomainFeature can exist, making this method impossible to call.
    ///
    /// - Parameter feature: The feature to check (no valid values exist).
    /// - Returns: Never returns as this method is unreachable.
    public func supports(_ feature: SecurityDomainSession.Feature) async -> Bool {
        // Unreachable - SecurityDomainFeature has no cases
    }

    /// Sends a **GET DATA** command to the card and returns the raw response bytes.
    ///
    /// - Parameters:
    ///   - tag: Two‑byte tag identifying the data object to read.
    ///   - data: Optional command data that will be included in the APDU body (may be `nil`).
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    /// - Returns: The data payload extracted from the successful APDU response.
    // @TraceScope
    public func getData(tag: UInt16, data: Data?) async throws(SCPError) -> Data {
        try await process(
            apdu: APDU(
                cla: 0x00,
                ins: 0xCA,
                p1: UInt8(tag >> 8),
                p2: UInt8(tag & 0xff),
                command: data
            )
        )
    }

    /// Sends a **STORE DATA** command containing the supplied payload.
    ///
    /// - Parameter data: The TLV‑encoded bytes to be written to the card.
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func putData(_ data: Data) async throws(SCPError) {
        try await process(apdu: APDU(cla: 0x00, ins: 0xE2, p1: 0x90, p2: 0x00, command: data))
    }

    /// Retrieves the card‑recognition data (**tag 0x66**).
    ///
    /// - Throws: ``SCPError`` if the command fails or the response format is invalid.
    /// - Returns: The raw **Card Recognition Data** object.
    // @TraceScope
    public func getCardRecognitionData() async throws(SCPError) -> Data {
        let data = try await self.getData(tag: 0x66, data: nil)
        guard let tlv = TKBERTLVRecord(from: data), tlv.tag == 0x73 else {
            throw .responseParseError("Malformed SCP response: expected tag 0x73", source: .here())
        }
        return tlv.value
    }

    /// Reads the **Key Information** table from the card.
    ///
    /// - Throws: ``SCPError`` if transmission fails or the response cannot be parsed.
    /// - Returns: A dictionary that maps each ``SCPKeyRef`` to a dictionary of component‑type bytes
    ///   (key usage) and their version numbers.
    // @TraceScope
    public func getKeyInformation() async throws(SCPError) -> [SCPKeyRef: [UInt8: UInt8]] {
        let tlvData: Data = try await self.getData(tag: 0xE0, data: nil)
        guard let tlvs = TKBERTLVRecord.sequenceOfRecords(from: tlvData) else {
            throw SCPError.responseParseError("Malformed SCP key info response", source: .here())
        }
        var keys = [SCPKeyRef: [UInt8: UInt8]]()
        for tlv in tlvs {
            if tlv.tag == 0xC0 {
                var data = tlv.value
                guard let kid = data.extract(1)?.uint8, let kvn = data.extract(1)?.uint8 else {
                    throw SCPError.responseParseError("Malformed SCP key reference data", source: .here())
                }
                let keyRef = SCPKeyRef(kid: kid, kvn: kvn)
                var components: [UInt8: UInt8] = [:]
                while data.count >= 2 {
                    guard let typeByte = data.extract(1)?.uint8, let versionByte = data.extract(1)?.uint8 else {
                        throw SCPError.responseParseError("Malformed SCP key component data", source: .here())
                    }
                    components[typeByte] = versionByte
                }
                keys[keyRef] = components
            }
        }

        return keys
    }

    /// Retrieves the certificate chain for a given key.
    ///
    /// - Parameter scpKeyRef: The key reference whose certificate chain is requested.
    ///
    /// - Throws: ``SCPError`` if the command fails or the response format is invalid.
    /// - Returns: An array of ``X509Cert`` objects representing the certificate chain.
    // @TraceScope
    public func getCertificateBundle(for keyRef: SCPKeyRef) async throws(SCPError) -> [X509Cert] {

        let data: Data
        do {
            data = try await getData(
                tag: 0xBF21,
                data: TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data
            )
        } catch {
            guard case let .failedResponse(response, _) = error else { throw error }
            if response.status == .referencedDataNotFound {
                return []
            } else {
                throw error
            }
        }
        guard let rawCerts = TKBERTLVRecord.sequenceOfRecords(from: data) else {
            throw .responseParseError("Malformed certificate response", source: .here())
        }
        let certs = rawCerts.map { X509Cert(der: $0.data) }
        return certs
    }

    /// Retrieves the CA identifiers (KLOC/KLCC) that the card currently stores.
    ///
    /// - Parameters:
    ///   - kloc: `true` to include **KLOC** identifiers (leaf certificate OCs); otherwise `false`.
    ///   - klcc: `true` to include **KLCC** identifiers (CA certificates); otherwise `false`.
    ///
    /// - Throws: ``SCPError`` if no identifiers are found when requested, command transmission fails,
    ///   or the response is malformed.
    /// - Returns: A dictionary mapping each ``SCPKeyRef`` to its associated identifier bytes.
    // @TraceScope
    public func getSupportedCAIdentifiers(kloc: Bool, klcc: Bool) async throws(SCPError) -> [SCPKeyRef: Data] {

        if !kloc && !klcc {
            throw .illegalArgument("At least one of kloc or klcc must be true", source: .here())
        }
        var data = Data()
        if kloc {
            do {
                data.append(try await getData(tag: 0xFF33, data: nil))
            } catch {
                if case let .failedResponse(response, _) = error,
                    response.status != .referencedDataNotFound
                {
                    throw error
                }
            }
        }

        if klcc {
            do {
                data.append(try await getData(tag: 0xFF34, data: nil))
            } catch {
                if case let .failedResponse(response, _) = error,
                    response.status != .referencedDataNotFound
                {
                    throw error
                }
            }
        }
        guard let tlvs = TKBERTLVRecord.sequenceOfRecords(from: data) else {
            throw .responseParseError("Malformed SCP key identifiers response", source: .here())
        }
        var identifiers = [SCPKeyRef: Data]()
        for i in stride(from: 0, to: tlvs.count, by: 2) {
            var ref = tlvs[i + 1].value
            guard let kid = ref.extract(1)?.uint8, let kvn = ref.extract(1)?.uint8 else {
                throw .responseParseError("Malformed SCP key identifier data", source: .here())
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
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func putCertificateBundle(_ certificates: [X509Cert], for keyRef: SCPKeyRef) async throws(SCPError) {

        var certsData = Data()
        certificates.forEach { certificate in
            certsData.append(certificate.der)
        }
        let data =
            TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data
            + TKBERTLVRecord(tag: 0xBF21, value: certsData).data
        try await putData(data)
    }

    /// Store which certificate serial numbers that can be used for a given key.
    ///
    /// Requires off-card entity verification.
    /// If no allowlist is stored, any certificate signed by the CA can be used.
    /// - Parameter keyRef: a reference to the key for which to store the allowlist
    /// - Parameter serials: the list of serial numbers to store
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func putAllowlist(for keyRef: SCPKeyRef, serials: [Data]) async throws(SCPError) {

        var serialsData = Data()
        serials.forEach { serial in
            serialsData.append(TKBERTLVRecord(tag: 0x93, value: serial).data)
        }
        let data =
            TKBERTLVRecord(tag: 0xA6, value: TKBERTLVRecord(tag: 0x83, value: keyRef.data).data).data
            + TKBERTLVRecord(tag: 0x70, value: serialsData).data
        try await putData(data)
    }

    /// Store the SKI (Subject Key Identifier) for the CA of a given key.
    /// Requires off-card entity verification.
    /// - Parameter keyRef: a reference to the key for which to store the CA issuer
    /// - Parameter ski: the Subject Key Identifier to store
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func putCAIssuer(for keyRef: SCPKeyRef, ski: Data) async throws(SCPError) {
        let klcc: UInt8
        switch keyRef.kid {
        case SCPKeyRef.Kid.scp11a, SCPKeyRef.Kid.scp11b, SCPKeyRef.Kid.scp11c: klcc = 1
        default: klcc = 0
        }
        let data = TKBERTLVRecord(
            tag: 0xA6,
            value: TKBERTLVRecord(tag: 0x80, value: klcc.data).data + TKBERTLVRecord(tag: 0x42, value: ski).data
                + TKBERTLVRecord(tag: 0x83, value: keyRef.data).data
        ).data
        try await putData(data)
    }

    /// Delete one (or more) keys.
    ///
    /// Requires off-card entity verification.
    /// All keys matching the given KID and/or KVN will be deleted (0 is treated as a wildcard).
    /// To delete the final key you must set deleteLast = true.
    /// - Parameter keyRef: a reference to the key to delete
    /// - Parameter deleteLast: must be true if deleting the final key, false otherwise
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func deleteKey(for keyRef: SCPKeyRef, deleteLast: Bool = false) async throws(SCPError) {
        var kid = keyRef.kid
        let kvn = keyRef.kvn

        if kid == 0 && kvn == 0 {
            throw .illegalArgument("Both KID and KVN cannot be zero", source: .here())
        }

        if kid == 1 || kid == 2 || kid == 3 {
            if kvn != 0 {
                kid = 0
            } else {
                throw .illegalArgument("KVN must be non-zero for KID 1, 2, or 3", source: .here())
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
        try await process(apdu: apdu)
    }

    /// Generate a new SCP11 key.
    ///
    /// Requires off-card entity verification.
    /// - Parameter keyRef: the KID-KVN pair to assign the new key
    /// - Parameter kvn: 0 to generate a new keypair, non-zero to replace an existing KVN
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the response format is invalid.
    /// - Returns: the public key from the generated key pair
    // @TraceScope
    public func generateECKey(for keyRef: SCPKeyRef, replacing kvn: UInt8) async throws(SCPError) -> EC.PublicKey {
        let params = TKBERTLVRecord(tag: 0xF0, value: Data([0x00])).data
        var data = Data()
        data.append(keyRef.kvn.data)
        data.append(contentsOf: params)

        let apdu = APDU(cla: 0x80, ins: 0xF1, p1: kvn, p2: keyRef.kid, command: data)

        let response = try await process(apdu: apdu)

        guard let tlv = TKBERTLVRecord(from: response), tlv.tag == 0xB0 else {
            throw SCPError.responseParseError("Malformed EC key response: expected tag 0xB0", source: .here())
        }

        guard let key = EC.PublicKey(uncompressedPoint: tlv.value, curve: .secp256r1) else {
            throw SCPError.dataProcessingError("Unable to parse EC public key from response", source: .here())
        }

        return key
    }

    /// Imports an SCP03 key set.
    /// Requires off-card entity verification.
    /// - Parameter keyRef: the KID-KVN pair to assign the new key set, KID must be 1
    /// - Parameter keys: the key material to import
    /// - Parameter kvn: 0 to generate a new keypair, non-zero to replace an existing KVN
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func putStaticKeys(_ keys: StaticKeys, for keyRef: SCPKeyRef, replacing kvn: UInt8) async throws(SCPError) {
        guard keyRef.kid == .scp03 else {
            throw .illegalArgument("KID must be 0x01 for SCP03 key sets", source: .here())
        }
        guard let dek = keys.dek else {
            throw .illegalArgument("New DEK must be set in static keys", source: .here())
        }
        guard let scpState else {
            throw SCPError.secureChannelRequired(source: .here())
        }

        var data = Data([keyRef.kvn])
        var expected = Data([keyRef.kvn])

        let defaultKcvIv: Data = .init(repeating: 0x01, count: 16)

        for key in [keys.enc, keys.mac, dek] {
            let kcv = try defaultKcvIv.cbcEncrypt(key: key).prefix(3)

            let currentDek = scpState.sessionKeys.dek!

            let encryptedKey = try key.cbcEncrypt(key: currentDek)
            data.append(TKBERTLVRecord(tag: 0x88, value: encryptedKey).data)
            data.append(UInt8(kcv.count))
            data.append(kcv)
            expected.append(kcv)
        }

        assert(data.bytes.count == 1 + 3 * (18 + 4), "Unexpected command data length")

        let apdu = APDU(cla: 0x80, ins: 0xD8, p1: kvn, p2: 0x80 | keyRef.kid, command: data)
        let resp = try await process(apdu: apdu)

        guard resp.constantTimeCompare(expected) else {
            throw .responseParseError("SCP key verification failed: response mismatch", source: .here())
        }

        /* Fix trace: trace(message: "SCP03 Key set imported") */
    }

    /// Imports a public key for SCP11a/c authentication of the off-card entity.
    ///
    /// - Parameters:
    ///   - keyRef: The KID/KVN pair where the new public key will be stored.
    ///   - publicKey: EC public key (must be prime256v1) used as CA to authenticate the off-card entity.
    ///   - kvn: Set to a non-zero KVN to delete/replace an existing key before import.
    /// - Throws: ``SCPError`` on validation failures or any error from the APDU exchange.
    // @TraceScope
    public func putPublicKey(
        _ publicKey: EC.PublicKey,
        for keyRef: SCPKeyRef,
        replacing kvn: UInt8
    ) async throws(SCPError) {

        // -- validate curve
        guard publicKey.curve == .secp256r1 else {
            throw .illegalArgument("Unsupported curve: \(publicKey.curve)", source: .here())
        }

        // -- TLV build
        var data = Data()
        data.append(keyRef.kvn)  // KVN

        data.append(TKBERTLVRecord(tag: 0xB0, value: publicKey.uncompressedPoint).data)  // EC point
        data.append(TKBERTLVRecord(tag: 0xF0, value: Data([0x00])).data)  // params = P-256
        data.append(0x00)  // END TLV list

        // -- send APDU
        let apdu = APDU(cla: 0x80, ins: 0xD8, p1: kvn, p2: keyRef.kid, command: data)
        let resp = try await process(apdu: apdu)

        // -- verify KCV
        guard resp.constantTimeCompare(Data([keyRef.kvn])) else {
            throw .responseParseError("SCP key store verification failed: KCV mismatch", source: .here())
        }

        /* Fix trace: trace(message: "SCP11 public key imported") */
    }

    /// Imports a secret key for SCP11.
    /// Requires off-card entity verification.
    /// - Parameter keyRef: the KID-KVN pair to assign the new secret key, KID must be 0x11, 0x13, or 0x15
    /// - Parameter privateKey: a private EC key used to authenticate the SD
    /// - Parameter kvn: 0 to generate a new keypair, non-zero to replace an existing KVN
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func putPrivateKey(
        _ privateKey: EC.PrivateKey,
        for keyRef: SCPKeyRef,
        replacing kvn: UInt8
    ) async throws(SCPError) {
        guard privateKey.curve == .secp256r1 else {
            throw .illegalArgument("Expected SECP256R1 private key", source: .here())
        }

        guard let scpState else {
            throw .secureChannelRequired(source: .here())
        }

        let rawSecret: Data
        do {
            let secretScalar = privateKey.k
            let p256 = try P256.Signing.PrivateKey(rawRepresentation: secretScalar)
            rawSecret = p256.rawRepresentation
            precondition(rawSecret.count == 32)
        } catch {
            throw .cryptoError("Failed to generate P256 key pair", error: error, source: .here())
        }

        let currentDek = scpState.sessionKeys.dek!
        let encryptedSecret = try rawSecret.cbcEncrypt(key: currentDek)
        precondition(encryptedSecret.count == 32)

        var data = Data()
        data.append(keyRef.kvn)
        data.append(TKBERTLVRecord(tag: 0xB1, value: encryptedSecret).data)
        data.append(TKBERTLVRecord(tag: 0xF0, value: Data([0x00])).data)
        data.append(0x00)

        let apdu = APDU(cla: 0x80, ins: 0xD8, p1: kvn, p2: keyRef.kid, command: data)
        let resp = try await process(apdu: apdu)
        guard resp.constantTimeCompare(Data([keyRef.kvn])) else {
            throw .responseParseError("SCP key deletion verification failed: KCV mismatch", source: .here())
        }

        /* Fix trace: trace(message: "SCP11 private key imported") */
    }

    /// Perform a factory reset of the Security Domain.
    /// This will remove all keys and associated data, as well as restore the default SCP03 static keys,
    /// and generate a new (attestable) SCP11b key.
    ///
    /// - Throws: ``SCPError`` if command transmission fails or the card returns an error status.
    // @TraceScope
    public func reset() async throws(SCPError) {
        let data = Data(repeating: 0x00, count: 8)
        let keyInfo = try await getKeyInformation()

        for (keyRefInitial, _) in keyInfo {
            var keyRef = keyRefInitial
            let ins: UInt8

            switch keyRef.kid {
            case SCPKeyRef.Kid.scp03:
                keyRef = SCPKeyRef(kid: 0, kvn: 0)
                ins = 0x50
            case 0x02, 0x03:
                continue  // Skip these as they are deleted by 0x01
            case SCPKeyRef.Kid.scp11a, SCPKeyRef.Kid.scp11c:
                ins = 0x82
            case SCPKeyRef.Kid.scp11b:
                ins = 0x88
            default:  // 0x10, 0x20-0x2F
                ins = 0x2A
            }

            let apdu = APDU(cla: 0x80, ins: ins, p1: keyRef.kvn, p2: keyRef.kid, command: data)

            for _ in 0..<65 {
                do {
                    _ = try await process(apdu: apdu)
                } catch let error {
                    guard case let .failedResponse(response, _) = error else {
                        throw error
                    }

                    let shouldExit =
                        switch response.status {
                        case .authMethodBlocked, .securityConditionNotSatisfied:
                            true
                        case .incorrectParameters:
                            false  // Continue loop
                        default:
                            throw error  // Re-throw
                        }
                    if shouldExit {
                        break  // This breaks out of the for loop
                    } else {
                        continue
                    }
                }
            }
        }
        /* Fix trace: trace(message: "SCP keys reset") */
    }

}

extension Data {
    fileprivate func cbcEncrypt(key: Data) throws(SCPError) -> Data {
        // zero IV for CBC
        let iv = Data(repeating: 0, count: kCCBlockSizeAES128)

        do {
            return try encrypt(algorithm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)
        } catch {
            throw SCPError.cryptoError("Failed to encrypt data with AES", error: error, source: .here())
        }
    }
}
