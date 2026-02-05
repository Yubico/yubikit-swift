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

// MARK: - Response Keys

extension CTAP2.CredentialManagement {
    fileprivate enum ResponseKey: Int {
        case existingResidentCredentialsCount = 0x01
        case maxPossibleRemainingResidentCredentialsCount = 0x02
        case rp = 0x03
        case rpIdHash = 0x04
        case totalRPs = 0x05
        case user = 0x06
        case credentialId = 0x07
        case publicKey = 0x08
        case totalCredentials = 0x09
        case credProtect = 0x0A
        case largeBlobKey = 0x0B
        case thirdPartyPayment = 0x0C
    }
}

// MARK: - Metadata + CBOR

extension CTAP2.CredentialManagement.Metadata: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        typealias Key = CTAP2.CredentialManagement.ResponseKey

        guard let existingCount = map[.int(Key.existingResidentCredentialsCount.rawValue)]?.uint64Value,
            let maxRemaining = map[.int(Key.maxPossibleRemainingResidentCredentialsCount.rawValue)]?.uint64Value
        else {
            return nil
        }

        self.init(
            existingCredentialsCount: UInt(existingCount),
            maxRemainingCredentialsCount: UInt(maxRemaining)
        )
    }
}

// MARK: - EnumerateRPsResponse + CBOR

extension CTAP2.CredentialManagement.EnumerateRPsResponse: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        typealias Key = CTAP2.CredentialManagement.ResponseKey

        // totalRPs (0x05) - only in first response
        let totalRPs: UInt?
        if let count = map[.int(Key.totalRPs.rawValue)]?.uint64Value {
            totalRPs = UInt(count)
        } else {
            totalRPs = nil
        }

        // rp (0x03) and rpIdHash (0x04)
        let rpData: CTAP2.CredentialManagement.RPData?
        if let rpCbor = map[.int(Key.rp.rawValue)],
            let rp: WebAuthn.PublicKeyCredential.RPEntity = rpCbor.cborDecoded(),
            let rpIdHash = map[.int(Key.rpIdHash.rawValue)]?.dataValue
        {
            rpData = CTAP2.CredentialManagement.RPData(rp: rp, rpIdHash: rpIdHash)
        } else {
            rpData = nil
        }

        self.init(rpData: rpData, totalRPs: totalRPs)
    }
}

// MARK: - EnumerateCredentialsResponse + CBOR

extension CTAP2.CredentialManagement.EnumerateCredentialsResponse: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        typealias Key = CTAP2.CredentialManagement.ResponseKey

        // totalCredentials (0x09) - only in first response
        let totalCredentials: UInt?
        if let count = map[.int(Key.totalCredentials.rawValue)]?.uint64Value {
            totalCredentials = UInt(count)
        } else {
            totalCredentials = nil
        }

        // Parse credential data
        let credentialData: CTAP2.CredentialManagement.CredentialData?
        if let userCbor = map[.int(Key.user.rawValue)],
            let user: WebAuthn.PublicKeyCredential.UserEntity = userCbor.cborDecoded(),
            let credIdCbor = map[.int(Key.credentialId.rawValue)],
            let credentialId: WebAuthn.PublicKeyCredential.Descriptor = credIdCbor.cborDecoded(),
            let publicKeyCbor = map[.int(Key.publicKey.rawValue)],
            let publicKey: COSE.Key = publicKeyCbor.cborDecoded()
        {
            // Optional: credProtect (0x0A)
            let credProtect: CTAP2.Extension.CredProtect.Level?
            if let protectValue = map[.int(Key.credProtect.rawValue)]?.uint64Value {
                credProtect = CTAP2.Extension.CredProtect.Level(rawValue: Int(protectValue))
            } else {
                credProtect = nil
            }

            // Optional: largeBlobKey (0x0B)
            let largeBlobKey = map[.int(Key.largeBlobKey.rawValue)]?.dataValue

            // Optional: thirdPartyPayment (0x0C)
            let thirdPartyPayment = map[.int(Key.thirdPartyPayment.rawValue)]?.boolValue

            credentialData = CTAP2.CredentialManagement.CredentialData(
                user: user,
                credentialId: credentialId,
                publicKey: publicKey,
                credProtect: credProtect,
                largeBlobKey: largeBlobKey,
                thirdPartyPayment: thirdPartyPayment
            )
        } else {
            credentialData = nil
        }

        self.init(credentialData: credentialData, totalCredentials: totalCredentials)
    }
}
