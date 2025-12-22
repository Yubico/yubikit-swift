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

import CryptoTokenKit
import Foundation
import OSLog

// Internal helper for SmartCard APDU communication with optional SCP encryption.
// Handles application selection, SCP setup, and APDU transmission with automatic continuation.
public final actor SmartCardInterface<Error: SmartCardSessionError>: Sendable {
    typealias Connection = SmartCardConnection

    let connection: Connection
    let scpState: SCPState?
    let selectResponse: Data

    // Flag to signal cancellation for CTAP operations over NFC
    internal var shouldCancelCTAP: Bool = false

    // Maximum message size for CTAP operations (CBORInterface)
    public private(set) var maxMsgSize: Int = 1024

    public func setMaxMsgSize(_ size: Int) {
        maxMsgSize = size
    }

    // Select application and optionally setup SCP
    init(
        connection: SmartCardConnection,
        application: Application,
        keyParams: SCPKeyParams? = nil,
        insSendRemaining: UInt8 = 0xc0
    ) async throws(Error) {
        self.connection = connection

        // Select application
        do {
            selectResponse = try await Self.sendPlainStatic(
                connection: connection,
                apdu: application.selectionCommand,
                insSendRemaining: insSendRemaining
            )
        } catch {
            guard let responseStatus = error.responseStatus else {
                throw error
            }
            // Convert application not found errors to featureNotSupported
            switch responseStatus.status {
            case .invalidInstruction, .fileNotFound:
                throw .featureNotSupported(source: .here())
            default:
                throw error
            }
        }

        // Setup SCP if needed
        if let keyParams {
            scpState = try await Self.setupSCP(
                connection: connection,
                keyParams: keyParams,
                insSendRemaining: insSendRemaining
            )
        } else {
            scpState = nil
        }
    }

    // Send APDU with optional SCP encryption and automatic continuation handling.
    // Returns response data only (status bytes stripped).
    @discardableResult
    func send(apdu: APDU, insSendRemaining: UInt8 = 0xc0) async throws(Error) -> Data {
        let response: Response = try await send(apdu: apdu, insSendRemaining: insSendRemaining)
        return response.data
    }

    // Sets a flag that will cause the next GET_RESPONSE poll to send P1_CANCEL_KEEP_ALIVE
    // instead of P1_KEEP_ALIVE, signaling the authenticator to abort the operation.
    func cancel() async throws(Error) where Error == CTAP2.SessionError {
        shouldCancelCTAP = true
    }

    // Internal variant that returns full Response and throws on non-success status.
    internal func send(
        apdu: APDU,
        insSendRemaining: UInt8 = 0xc0,
    ) async throws(Error) -> Response {
        let response: Response
        if let scpState {
            response = try await sendWithSCP(apdu: apdu, scpState: scpState, insSendRemaining: insSendRemaining)
        } else {
            response = try await sendPlain(apdu: apdu, insSendRemaining: insSendRemaining)
        }
        guard response.status == .ok else {
            throw .failedResponse(response, source: .here())
        }
        return response
    }

    // Send APDU with SCP encryption/decryption.
    // Flow: encrypt command → compute MAC → send → verify response MAC → decrypt response.
    // Returns the decrypted response with original status code (status check happens in caller).
    private func sendWithSCP(
        apdu: APDU,
        scpState: SCPState,
        insSendRemaining: UInt8
    ) async throws(Error) -> Response {
        // Encrypt command data
        let data: Data
        do {
            data = try await scpState.encrypt(apdu.command ?? Data())
        } catch {
            throw .cryptoError("Failed to encrypt APDU command", error: error, source: .here())
        }

        // Set CLA secure messaging bit
        let cla = apdu.cla | 0x04

        // Calculate MAC over encrypted APDU
        let mac: Data
        do {
            mac = try await scpState.mac(
                data: APDU(
                    cla: cla,
                    ins: apdu.ins,
                    p1: apdu.p1,
                    p2: apdu.p2,
                    command: data + Data(count: 8)
                ).data.dropLast(8)
            )
        } catch {
            throw .cryptoError("Failed to calculate MAC", error: error, source: .here())
        }

        // Send encrypted APDU with MAC
        let secureApdu = APDU(cla: cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, command: data + mac)
        let response = try await sendPlain(apdu: secureApdu, insSendRemaining: insSendRemaining)
        var result = response.data
        let sw = response.responseStatus.rawStatus

        // Verify and remove MAC from response
        if !result.isEmpty {
            do {
                result = try await scpState.unmac(data: result, sw: sw)
            } catch {
                throw .scpError(error, source: .here())
            }
        }

        // Decrypt response data
        if !result.isEmpty {
            do {
                result = try await scpState.decrypt(result)
            } catch {
                throw .cryptoError("Failed to decrypt result", error: error, source: .here())
            }
        }

        // Return response with decrypted data and original status
        return Response(rawData: result + Data([response.responseStatus.sw1, response.responseStatus.sw2]))
    }

    // Send APDU without SCP.
    // Returns the response with status code (status check happens in caller).
    private func sendPlain(apdu: APDU, insSendRemaining: UInt8) async throws(Error) -> Response {
        try await Self.sendWithContinuationStatic(
            connection: connection,
            apdu: apdu,
            accumulated: Data(),
            readMoreData: false,
            insSendRemaining: insSendRemaining
        )
    }

    // Send APDU without SCP (static version).
    // Used during actor init before instance methods are available.
    private static func sendPlainStatic(
        connection: SmartCardConnection,
        apdu: APDU,
        insSendRemaining: UInt8
    ) async throws(Error) -> Data {
        let response = try await sendWithContinuationStatic(
            connection: connection,
            apdu: apdu,
            accumulated: Data(),
            readMoreData: false,
            insSendRemaining: insSendRemaining
        )
        guard response.status == .ok else {
            throw .failedResponse(response, source: .here())
        }
        return response.data
    }

    // Send APDU and handle continuation responses (0x61).
    // Used during actor init before instance methods are available.
    private static func sendWithContinuationStatic(
        connection: SmartCardConnection,
        apdu: APDU,
        accumulated: Data,
        readMoreData: Bool,
        insSendRemaining: UInt8
    ) async throws(Error) -> Response {
        // Send APDU or continuation command
        let responseData: Data
        do {
            if readMoreData {
                let continueApdu = APDU(cla: 0, ins: insSendRemaining, p1: 0, p2: 0, command: nil)
                responseData = try await connection.send(data: continueApdu.data)
            } else {
                responseData = try await connection.send(data: apdu.data)
            }
        } catch {
            throw .connectionError(error, source: .here())
        }

        // Parse response status
        let response = Response(rawData: responseData)

        // Only continue accumulation for 0x61 (more data) or 0x9000 (success)
        // Other statuses (including errors and keepalive 0x9100) return immediately
        guard response.status == .ok || response.responseStatus.sw1 == 0x61 else {
            return Response(
                data: accumulated + response.data,
                sw1: response.responseStatus.sw1,
                sw2: response.responseStatus.sw2
            )
        }

        // Accumulate data
        let newData = accumulated + response.data

        // Handle continuation
        if response.responseStatus.sw1 == 0x61 {
            return try await sendWithContinuationStatic(
                connection: connection,
                apdu: apdu,
                accumulated: newData,
                readMoreData: true,
                insSendRemaining: insSendRemaining
            )
        } else {
            // Return full response with accumulated data and final status
            return Response(rawData: newData + Data([response.responseStatus.sw1, response.responseStatus.sw2]))
        }
    }

    // Setup SCP03 or SCP11 based on keyParams type
    private static func setupSCP(
        connection: SmartCardConnection,
        keyParams: SCPKeyParams,
        insSendRemaining: UInt8
    ) async throws(Error) -> SCPState {
        if let scp03Params = keyParams as? SCP03KeyParams {
            return try await setupSCP03(
                connection: connection,
                keyParams: keyParams,
                staticKeys: scp03Params.staticKeys,
                insSendRemaining: insSendRemaining
            )
        }

        if let scp11Params = keyParams as? SCP11KeyParams {
            return try await setupSCP11(
                connection: connection,
                keyParams: keyParams,
                scp11Params: scp11Params,
                insSendRemaining: insSendRemaining
            )
        }

        // Not implemented
        throw .featureNotSupported(source: .here())
    }

    // Setup SCP03
    private static func setupSCP03(
        connection: SmartCardConnection,
        keyParams: SCPKeyParams,
        staticKeys: StaticKeys,
        insSendRemaining: UInt8
    ) async throws(Error) -> SCPState {
        let hostChallenge = Data.random(length: 8)

        var result = try await sendPlainStatic(
            connection: connection,
            apdu: APDU(
                cla: 0x80,
                ins: 0x50,  // INITIALIZE UPDATE
                p1: keyParams.keyRef.kvn,
                p2: 0x00,
                command: hostChallenge
            ),
            insSendRemaining: insSendRemaining
        )

        guard let _ = result.extract(10),  // diversificationData
            let _ = result.extract(3),  // keyInfo
            let cardChallenge = result.extract(8),
            let cardCryptogram = result.extract(8)
        else {
            throw .responseParseError("Malformed SCP03 response", source: .here())
        }

        let context = hostChallenge + cardChallenge
        let sessionKeys = staticKeys.derive(context: context)

        let genCardCryptogram: Data
        do {
            genCardCryptogram = try StaticKeys.deriveKey(key: sessionKeys.smac, t: 0x00, context: context, l: 0x40)
        } catch {
            throw .cryptoError("Failed to derive card cryptogram", error: error, source: .here())
        }

        guard genCardCryptogram.constantTimeCompare(cardCryptogram) == true else {
            throw .responseParseError("Wrong SCP03 key set", source: .here())
        }

        let hostCryptogram: Data
        do {
            hostCryptogram = try StaticKeys.deriveKey(key: sessionKeys.smac, t: 0x01, context: context, l: 0x40)
        } catch {
            throw .cryptoError("Failed to derive host cryptogram", error: error, source: .here())
        }

        let state = SCPState(sessionKeys: sessionKeys, macChain: Data(count: 16))

        // Send finalize with SCP MAC (no encryption)
        let finalizeApdu = APDU(cla: 0x84, ins: 0x82, p1: 0x33, p2: 0, command: hostCryptogram)
        _ = try await sendWithSCPNoEncryptStatic(
            connection: connection,
            apdu: finalizeApdu,
            scpState: state,
            insSendRemaining: insSendRemaining
        )

        return state
    }

    // Setup SCP11
    private static func setupSCP11(
        connection: SmartCardConnection,
        keyParams: SCPKeyParams,
        scp11Params: SCP11KeyParams,
        insSendRemaining: UInt8
    ) async throws(Error) -> SCPState {
        let kid = keyParams.keyRef.kid

        let params: UInt8
        switch kid {
        case .scp11a:
            params = 0b01
        case .scp11b:
            params = 0b00
        case .scp11c:
            params = 0b11
        default:
            throw .illegalArgument("Invalid SCP11 KID", source: .here())
        }

        // Load the OCE certificate chain for SCP11a / SCP11c
        if kid == .scp11a || kid == .scp11c {
            let certificates = scp11Params.certificates
            guard !certificates.isEmpty else {
                throw .illegalArgument("SCP11a and SCP11c require a certificate chain", source: .here())
            }

            let oceRef = scp11Params.oceKeyRef ?? SCPKeyRef(kid: 0x00, kvn: 0x00)

            for (index, cert) in certificates.enumerated() {
                let p2: UInt8 = oceRef.kid | (index < certificates.count - 1 ? 0x80 : 0x00)
                _ = try await sendPlainStatic(
                    connection: connection,
                    apdu: APDU(
                        cla: 0x80,
                        ins: 0x2A,  // PERFORM SECURITY OPERATION
                        p1: oceRef.kvn,
                        p2: p2,
                        command: cert.der
                    ),
                    insSendRemaining: insSendRemaining
                )
            }
        }

        let keyUsage = Data([0x3c])
        let keyType = Data([0x88])
        let keyLen = Data([16])

        let pkSdEcka = scp11Params.pkSdEcka

        guard let eskOceEcka = EC.PrivateKey.random(curve: .secp256r1) else {
            throw .cryptoError("Failed to generate private key", error: nil, source: .here())
        }
        let epkOceEcka = eskOceEcka.publicKey
        let epkOceEckaData = epkOceEcka.uncompressedPoint

        let data =
            TKBERTLVRecord(
                tag: 0xa6,
                value: TKBERTLVRecord(tag: 0x90, value: Data([0x11, params])).data
                    + TKBERTLVRecord(tag: 0x95, value: keyUsage).data
                    + TKBERTLVRecord(tag: 0x80, value: keyType).data
                    + TKBERTLVRecord(tag: 0x81, value: keyLen).data
            ).data + TKBERTLVRecord(tag: 0x5f49, value: epkOceEckaData).data

        let skOceEcka = scp11Params.skOceEcka ?? eskOceEcka
        let ins: UInt8 = kid == .scp11b ? 0x88 : 0x82

        let response = try await sendPlainStatic(
            connection: connection,
            apdu: APDU(
                cla: 0x80,
                ins: ins,
                p1: keyParams.keyRef.kvn,
                p2: keyParams.keyRef.kid,
                command: data
            ),
            insSendRemaining: insSendRemaining
        )

        guard let tlvs = TKBERTLVRecord.sequenceOfRecords(from: response), tlvs.count == 2 else {
            throw .responseParseError("Malformed SCP11 response: expected 2 TLV records", source: .here())
        }
        guard tlvs[0].tag == 0x5f49, tlvs[1].tag == 0x86 else {
            throw .responseParseError("Malformed SCP11 response: unexpected TLV tags", source: .here())
        }

        let epkSdEckaEncodedPoint = tlvs[0].value
        let receipt = tlvs[1].value
        let keyAgreementData = data + tlvs[0].data
        let sharedInfo = keyUsage + keyType + keyLen

        guard let epkSdEcka = EC.PublicKey(uncompressedPoint: epkSdEckaEncodedPoint, curve: .secp256r1) else {
            throw .dataProcessingError("Unable to parse EC public key", source: .here())
        }

        guard let keyAgreement1 = eskOceEcka.sharedSecret(with: epkSdEcka),
            let keyAgreement2 = skOceEcka.sharedSecret(with: pkSdEcka)
        else {
            throw .cryptoError("Unable to generate shared secret", error: nil, source: .here())
        }

        let keyMaterial = keyAgreement1 + keyAgreement2
        var keys = [Data]()

        for counter in UInt32(1)...UInt32(4) {
            let data = keyMaterial + counter.bigEndian.data + sharedInfo
            var digest = data.sha256()
            keys.append(digest.extract(16)!)
            keys.append(digest)
        }

        let genReceipt: Data
        do {
            genReceipt = try keyAgreementData.aescmac(key: keys[0])
        } catch {
            throw .cryptoError("Failed to generate receipt", error: error, source: .here())
        }

        guard genReceipt.constantTimeCompare(receipt) else {
            throw .responseParseError("Receipt does not match", source: .here())
        }

        let sessionKeys = SCPSessionKeys(senc: keys[1], smac: keys[2], srmac: keys[3], dek: keys[4])
        return SCPState(sessionKeys: sessionKeys, macChain: receipt)
    }

    // Send APDU with SCP but without encryption (static version for SCP setup)
    private static func sendWithSCPNoEncryptStatic(
        connection: SmartCardConnection,
        apdu: APDU,
        scpState: SCPState,
        insSendRemaining: UInt8
    ) async throws(Error) -> Data {
        let data = apdu.command ?? Data()
        let cla = apdu.cla | 0x04

        let mac: Data
        do {
            mac = try await scpState.mac(
                data: APDU(
                    cla: cla,
                    ins: apdu.ins,
                    p1: apdu.p1,
                    p2: apdu.p2,
                    command: data + Data(count: 8)
                ).data.dropLast(8)
            )
        } catch {
            throw .cryptoError("Failed to calculate MAC", error: error, source: .here())
        }

        let secureApdu = APDU(cla: cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, command: data + mac)
        var result = try await sendPlainStatic(
            connection: connection,
            apdu: secureApdu,
            insSendRemaining: insSendRemaining
        )

        // sendPlainStatic already threw if status != 0x9000
        if !result.isEmpty {
            do {
                result = try await scpState.unmac(data: result, sw: 0x9000)
            } catch {
                throw .scpError(error, source: .here())
            }
        }

        return result
    }
}

extension Application {
    fileprivate var selectionCommand: APDU {
        let data: Data
        switch self {
        case .oath:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
        case .management:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])
        case .piv:
            data = Data([0xA0, 0x00, 0x00, 0x03, 0x08])
        case .securityDomain:
            data = Data([0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00])
        case .fido2:
            data = Data([0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
        }

        return APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, command: data)
    }
}

extension EC.PrivateKey {
    // Perform ECDH key-agreement and return the raw shared secret bytes
    fileprivate func sharedSecret(with publicKey: EC.PublicKey) -> Data? {
        guard let privateSecKey = asSecKey(), let associatedPublicSecKey = publicKey.asSecKey() else {
            return nil
        }

        var cfError: Unmanaged<CFError>?
        guard
            let secretData = SecKeyCopyKeyExchangeResult(
                privateSecKey,
                .ecdhKeyExchangeStandard,
                associatedPublicSecKey,
                [:] as CFDictionary,
                &cfError
            ) as Data?
        else {
            return nil
        }

        return secretData
    }
}
