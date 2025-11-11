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

// MARK: - AuthenticatorInfo + CBOR

extension AuthenticatorInfo: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: versions (0x01) - array of strings
        guard let versionsValue = map[.unsignedInt(0x01)]?.arrayValue,
            let versions = versionsValue.compactMap({ $0.stringValue }) as [String]?,
            !versions.isEmpty
        else {
            return nil
        }

        // Required: aaguid (0x03) - 16-byte byte string
        guard let aaguid = map[.unsignedInt(0x03)]?.dataValue,
            aaguid.count == 16
        else {
            return nil
        }

        // Optional: extensions (0x02) - defaults to empty array
        let extensions = map[.unsignedInt(0x02)]?.arrayValue?.compactMap { $0.stringValue } ?? []

        // Optional: options (0x04) - defaults to empty dictionary
        var options: [String: Bool] = [:]
        if let optionsMap = map[.unsignedInt(0x04)]?.mapValue {
            for (key, value) in optionsMap {
                if let keyString = key.stringValue, let valueBool = value.boolValue {
                    options[keyString] = valueBool
                }
            }
        }

        // Optional: maxMsgSize (0x05) - defaults to 1024
        let maxMsgSize = map[.unsignedInt(0x05)]?.uint64Value.map { UInt($0) } ?? 1024

        // Optional: pinUvAuthProtocols (0x06) - defaults to empty array
        let pinUvAuthProtocols =
            map[.unsignedInt(0x06)]?.arrayValue?.compactMap {
                $0.uint64Value.map { UInt($0) }
            } ?? []

        // Optional: maxCredentialCountInList (0x07)
        let maxCredentialCountInList = map[.unsignedInt(0x07)]?.uint64Value.map { UInt($0) }

        // Optional: maxCredentialIdLength (0x08)
        let maxCredentialIdLength = map[.unsignedInt(0x08)]?.uint64Value.map { UInt($0) }

        // Optional: transports (0x09)
        let transports = map[.unsignedInt(0x09)]?.arrayValue?.compactMap { $0.stringValue }

        // Optional: algorithms (0x0A) - array of integers (can be negative)
        let algorithms = map[.unsignedInt(0x0A)]?.arrayValue?.compactMap { $0.intValue }

        // Optional: maxSerializedLargeBlobArray (0x0B)
        let maxSerializedLargeBlobArray = map[.unsignedInt(0x0B)]?.uint64Value.map { UInt($0) }

        // Optional: forcePINChange (0x0C)
        let forcePINChange = map[.unsignedInt(0x0C)]?.boolValue

        // Optional: minPINLength (0x0D)
        let minPINLength = map[.unsignedInt(0x0D)]?.uint64Value.map { UInt($0) }

        // Optional: firmwareVersion (0x0E)
        let firmwareVersion = map[.unsignedInt(0x0E)]?.uint64Value.map { UInt($0) }

        // Optional: maxCredBlobLength (0x0F)
        let maxCredBlobLength = map[.unsignedInt(0x0F)]?.uint64Value.map { UInt($0) }

        // Optional: maxRPIDsForSetMinPINLength (0x10)
        let maxRPIDsForSetMinPINLength = map[.unsignedInt(0x10)]?.uint64Value.map { UInt($0) }

        // Optional: preferredPlatformUvAttempts (0x11)
        let preferredPlatformUvAttempts = map[.unsignedInt(0x11)]?.uint64Value.map { UInt($0) }

        // Optional: uvModality (0x12)
        let uvModality = map[.unsignedInt(0x12)]?.uint64Value.map { UInt($0) }

        // Optional: certifications (0x13) - map, keeping as Any for now
        // This is complex and rarely used, so we'll skip detailed parsing

        // Optional: remainingDiscoverableCredentials (0x14)
        let remainingDiscoverableCredentials = map[.unsignedInt(0x14)]?.uint64Value.map { UInt($0) }

        // Optional: vendorPrototypeConfigCommands (0x15)
        let vendorPrototypeConfigCommands = map[.unsignedInt(0x15)]?.arrayValue?.compactMap {
            $0.uint64Value.map { UInt($0) }
        }

        self.init(
            versions: versions,
            aaguid: aaguid,
            extensions: extensions,
            options: options,
            maxMsgSize: maxMsgSize,
            pinUvAuthProtocols: pinUvAuthProtocols,
            maxCredentialCountInList: maxCredentialCountInList,
            maxCredentialIdLength: maxCredentialIdLength,
            transports: transports,
            algorithms: algorithms,
            maxSerializedLargeBlobArray: maxSerializedLargeBlobArray,
            forcePINChange: forcePINChange,
            minPINLength: minPINLength,
            firmwareVersion: firmwareVersion,
            maxCredBlobLength: maxCredBlobLength,
            maxRPIDsForSetMinPINLength: maxRPIDsForSetMinPINLength,
            preferredPlatformUvAttempts: preferredPlatformUvAttempts,
            uvModality: uvModality,
            remainingDiscoverableCredentials: remainingDiscoverableCredentials,
            vendorPrototypeConfigCommands: vendorPrototypeConfigCommands
        )
    }
}
