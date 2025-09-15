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

private let insInitializeUpdate: UInt8 = 0x50

typealias SCPKid = SCPKeyRef.Kid

internal actor SCPProcessor: HasSCPLogger {

    internal var state: SCPState

    internal init(connection: SmartCardConnection, keyParams: SCPKeyParams, insSendRemaining: UInt8 = 0xc0) async throws
    {
        if let scp03Params = keyParams as? SCP03KeyParams {
            let hostChallenge = Data.random(length: 8)
            Self.trace(message: "send challenge: \(hostChallenge.hexEncodedString)")
            var result = try await connection.send(
                apdu: APDU(
                    cla: 0x80,
                    ins: insInitializeUpdate,
                    p1: keyParams.keyRef.kvn,
                    p2: 0x00,
                    command: hostChallenge,
                    type: .extended
                ),
                insSendRemaining: insSendRemaining
            )

            guard let _ = result.extract(10),  // diversificationData
                let _ = result.extract(3),  // keyInfo
                let cardChallenge = result.extract(8),
                let cardCryptogram = result.extract(8)
            else {
                throw SCPError.unexpectedResponse("Malformed SCP03 response")
            }

            let context = hostChallenge + cardChallenge
            let sessionKeys = scp03Params.staticKeys.derive(context: context)

            let genCardCryptogram = try StaticKeys.deriveKey(key: sessionKeys.smac, t: 0x00, context: context, l: 0x40)

            guard genCardCryptogram.constantTimeCompare(cardCryptogram) == true else {
                throw SCPError.unexpectedResponse("Wrong SCP03 key set")
            }

            let hostCryptogram = try StaticKeys.deriveKey(key: sessionKeys.smac, t: 0x01, context: context, l: 0x40)

            self.state = SCPState(sessionKeys: sessionKeys, macChain: Data(count: 16))

            let finalizeApdu = APDU(cla: 0x84, ins: 0x82, p1: 0x33, p2: 0, command: hostCryptogram, type: .extended)
            _ = try await self.send(
                apdu: finalizeApdu,
                using: connection,
                encrypt: false,
                insSendRemaining: insSendRemaining
            )

            trace(message: "done configuring SCP03")
            return
        }

        if let scp11Params = keyParams as? SCP11KeyParams {
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
                throw SCPError.illegalArgument("Invalid SCP11 KID")
            }

            // Load the OCE certificate chain for SCP11a / SCP11c (GPC v2.3 Amend F §7.5)
            if kid == .scp11a || kid == .scp11c {
                let certificates = scp11Params.certificates
                guard !certificates.isEmpty else {
                    throw SCPError.illegalArgument("SCP11a and SCP11c require a certificate chain")
                }

                // Use provided OCE key reference or fall back to (kvn:0x00, kid:0x00)
                let oceRef = scp11Params.oceKeyRef ?? SCPKeyRef(kid: 0x00, kvn: 0x00)

                for (index, cert) in certificates.enumerated() {
                    // For every cert except the last, set bit 7 of P2 to indicate "more blocks"
                    let p2: UInt8 = oceRef.kid | (index < certificates.count - 1 ? 0x80 : 0x00)
                    Self.trace(message: "sending certificate \(index)")
                    _ = try await connection.send(
                        apdu: APDU(
                            cla: 0x80,
                            ins: 0x2A,  // PERFORM SECURITY OPERATION
                            p1: oceRef.kvn,  // 3
                            p2: p2,  // -112
                            command: cert.der,
                            type: .extended
                        )
                    )
                }
            }

            let keyUsage = Data([0x3c])  // AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION
            let keyType = Data([0x88])  // AES
            let keyLen = Data([16])  // 128-bit

            let pkSdEcka = scp11Params.pkSdEcka
            Self.trace(message: "pkSdEcka: \(pkSdEcka.uncompressedPoint.hexEncodedString)")

            guard let eskOceEcka = EC.PrivateKey.random(curve: .p256) else {
                throw SCPError.encryptionFailed("Failed to generate private key")
            }
            let epkOceEcka = eskOceEcka.publicKey

            let epkOceEckaData = epkOceEcka.uncompressedPoint
            Self.trace(message: "epkOceEckaData: \(epkOceEckaData.hexEncodedString)")

            Self.trace(message: "params: \(Data([0x11, params]).hexEncodedString)")

            // GPC v2.3 Amendment F (SCP11) v1.4 §7.6.2.3
            let data =
                TKBERTLVRecord(
                    tag: 0xa6,
                    value: TKBERTLVRecord(tag: 0x90, value: Data([0x11, params])).data
                        + TKBERTLVRecord(tag: 0x95, value: keyUsage).data
                        + TKBERTLVRecord(tag: 0x80, value: keyType).data + TKBERTLVRecord(tag: 0x81, value: keyLen).data
                ).data + TKBERTLVRecord(tag: 0x5f49, value: epkOceEckaData).data
            Self.trace(message: "data: \(data.hexEncodedString)")
            let skOceEcka = scp11Params.skOceEcka ?? eskOceEcka
            let ins: UInt8 = kid == .scp11b ? 0x88 : 0x82
            Self.trace(
                message:
                    "sending: \(APDU(cla: 0x80, ins: ins, p1: keyParams.keyRef.kvn, p2: keyParams.keyRef.kid, command: data, type: .extended))"
            )
            let response = try await connection.send(
                apdu: APDU(
                    cla: 0x80,
                    ins: ins,
                    p1: keyParams.keyRef.kvn,
                    p2: keyParams.keyRef.kid,
                    command: data,
                    type: .extended
                )
            )

            guard let tlvs = TKBERTLVRecord.sequenceOfRecords(from: response), tlvs.count == 2 else {
                throw SCPError.unexpectedResponse
            }
            guard tlvs[0].tag == 0x5f49, tlvs[1].tag == 0x86 else {
                throw SCPError.unexpectedResponse
            }
            let epkSdEckaEncodedPoint = tlvs[0].value
            let receipt = tlvs[1].value
            let keyAgreementData = data + tlvs[0].data
            let sharedInfo = keyUsage + keyType + keyLen

            guard let epkSdEcka = EC.PublicKey(uncompressedPoint: epkSdEckaEncodedPoint) else {
                throw SCPError.notSupported("Unable to parse EC public key")
            }

            guard let keyAgreement1 = eskOceEcka.sharedSecret(with: epkSdEcka),
                let keyAgreement2 = skOceEcka.sharedSecret(with: pkSdEcka)
            else {
                throw SCPError.encryptionFailed("Unable to generate shared secret")
            }
            let keyMaterial = keyAgreement1 + keyAgreement2

            var keys = [Data]()

            for counter in UInt32(1)...UInt32(4) {
                Self.trace(message: "counter: \(counter.bigEndian)")
                Self.trace(message: "hex counter: \(counter.bigEndian.data.hexEncodedString)")
                let data = keyMaterial + counter.bigEndian.data + sharedInfo
                var digest = data.sha256()
                keys.append(digest.extract(16)!)
                keys.append(digest)
            }

            Self.trace(message: "keys[0]: \(keys[0].hexEncodedString)")
            let genReceipt = try keyAgreementData.aescmac(key: keys[0])

            Self.trace(message: "receipt: \(receipt.hexEncodedString)")
            Self.trace(message: "genReceipt: \(genReceipt.hexEncodedString)")

            guard genReceipt.constantTimeCompare(receipt) else {
                throw SCPError.unexpectedResponse("Receipt does not match")
            }

            let sessionKeys = SCPSessionKeys(senc: keys[1], smac: keys[2], srmac: keys[3], dek: keys[4])
            self.state = SCPState(sessionKeys: sessionKeys, macChain: receipt)

            Self.trace(message: "done configuring SCP11")
            return
        }

        // Not implemented
        throw SCPError.notSupported
    }

    internal init(state: SCPState) {
        self.state = state
    }

    internal func send(
        apdu: APDU,
        using connection: any SmartCardConnection,
        insSendRemaining: UInt8 = 0xc0
    ) async throws -> Data {
        try await self.send(apdu: apdu, using: connection, encrypt: true, insSendRemaining: insSendRemaining)
    }

    private func send(
        apdu: APDU,
        using connection: any SmartCardConnection,
        encrypt: Bool,
        insSendRemaining: UInt8
    ) async throws -> Data {
        trace(message: "send(... encrypt: \(encrypt)) \(apdu), \(state)")
        let data: Data
        if encrypt {
            data = try state.encrypt(apdu.command ?? Data())
        } else {
            data = apdu.command ?? Data()
        }
        let cla = apdu.cla | 0x04

        let mac = try state.mac(
            data: APDU(
                cla: cla,
                ins: apdu.ins,
                p1: apdu.p1,
                p2: apdu.p2,
                command: data + Data(count: 8),
                type: .extended
            ).data.dropLast(8)
        )

        let apdu = APDU(cla: cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, command: data + mac, type: .extended)
        trace(message: "processed apdu: \(apdu)")
        var result = try await connection.send(apdu: apdu, insSendRemaining: insSendRemaining)

        if !result.isEmpty {
            result = try state.unmac(data: result, sw: 0x9000)
        }
        if !result.isEmpty {
            result = try state.decrypt(result)
        }

        return result
    }
}

extension EC.PrivateKey {
    // Perform an ECDH key-agreement with the passed public key
    // and return the raw shared secret bytes.
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
