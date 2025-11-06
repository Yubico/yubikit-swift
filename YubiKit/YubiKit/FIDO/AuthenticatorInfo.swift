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

/// Information about a FIDO2/CTAP2 authenticator.
///
/// This structure contains the response from the `authenticatorGetInfo` command,
/// providing details about the authenticator's capabilities, supported features,
/// and configuration.
struct AuthenticatorInfo: Sendable {

    // MARK: - Required Fields

    /// List of supported CTAP protocol versions (e.g., "FIDO_2_0", "FIDO_2_1").
    let versions: [String]

    /// The authenticator's AAGUID (Authenticator Attestation Global Unique ID).
    /// This is a 128-bit identifier that indicates the type/model of authenticator.
    let aaguid: Data

    /// List of supported extensions (e.g., "hmac-secret", "credProtect").
    let extensions: [String]

    /// Supported authenticator options with their current values.
    let options: [String: Bool]

    /// Maximum message size supported by the authenticator in bytes.
    let maxMsgSize: UInt

    /// List of supported PIN/UV authentication protocol versions.
    let pinUvAuthProtocols: [UInt]

    // MARK: - Optional Fields

    /// Maximum number of credentials that can be sent in allowList.
    let maxCredentialCountInList: UInt?

    /// Maximum length of credential ID in bytes.
    let maxCredentialIdLength: UInt?

    /// Supported transports (e.g., "usb", "nfc", "ble").
    let transports: [String]?

    /// List of supported cryptographic algorithms (COSE algorithm identifiers).
    let algorithms: [Int]?

    /// Maximum size of serialized large blob array in bytes.
    let maxSerializedLargeBlobArray: UInt?

    /// Indicates if PIN change is required before further operations.
    let forcePINChange: Bool?

    /// Minimum PIN length required by the authenticator.
    let minPINLength: UInt?

    /// Firmware version number.
    let firmwareVersion: UInt?

    /// Maximum length of credential blob in bytes.
    let maxCredBlobLength: UInt?

    /// Maximum number of RP IDs for setMinPINLength.
    let maxRPIDsForSetMinPINLength: UInt?

    /// Preferred number of platform UV attempts.
    let preferredPlatformUvAttempts: UInt?

    /// User verification modality.
    let uvModality: UInt?

    /// Authenticator certifications.
    /// Note: Skipped for now due to complexity and rare usage.
    // let certifications: [String: Any]?

    /// Remaining discoverable credential slots.
    let remainingDiscoverableCredentials: UInt?

    /// Supported vendor prototype config commands.
    let vendorPrototypeConfigCommands: [UInt]?

    // MARK: - Initialization

    init(
        versions: [String],
        aaguid: Data,
        extensions: [String] = [],
        options: [String: Bool] = [:],
        maxMsgSize: UInt = 1024,
        pinUvAuthProtocols: [UInt] = [],
        maxCredentialCountInList: UInt? = nil,
        maxCredentialIdLength: UInt? = nil,
        transports: [String]? = nil,
        algorithms: [Int]? = nil,
        maxSerializedLargeBlobArray: UInt? = nil,
        forcePINChange: Bool? = nil,
        minPINLength: UInt? = nil,
        firmwareVersion: UInt? = nil,
        maxCredBlobLength: UInt? = nil,
        maxRPIDsForSetMinPINLength: UInt? = nil,
        preferredPlatformUvAttempts: UInt? = nil,
        uvModality: UInt? = nil,
        remainingDiscoverableCredentials: UInt? = nil,
        vendorPrototypeConfigCommands: [UInt]? = nil
    ) {
        self.versions = versions
        self.aaguid = aaguid
        self.extensions = extensions
        self.options = options
        self.maxMsgSize = maxMsgSize
        self.pinUvAuthProtocols = pinUvAuthProtocols
        self.maxCredentialCountInList = maxCredentialCountInList
        self.maxCredentialIdLength = maxCredentialIdLength
        self.transports = transports
        self.algorithms = algorithms
        self.maxSerializedLargeBlobArray = maxSerializedLargeBlobArray
        self.forcePINChange = forcePINChange
        self.minPINLength = minPINLength
        self.firmwareVersion = firmwareVersion
        self.maxCredBlobLength = maxCredBlobLength
        self.maxRPIDsForSetMinPINLength = maxRPIDsForSetMinPINLength
        self.preferredPlatformUvAttempts = preferredPlatformUvAttempts
        self.uvModality = uvModality
        self.remainingDiscoverableCredentials = remainingDiscoverableCredentials
        self.vendorPrototypeConfigCommands = vendorPrototypeConfigCommands
    }
}

// MARK: - CBOR Decoding

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

        // extensions (0x02) - defaults to empty array
        let extensions = map[.unsignedInt(0x02)]?.arrayValue?.compactMap { $0.stringValue } ?? []

        // options (0x04) - defaults to empty dictionary
        var options: [String: Bool] = [:]
        if let optionsMap = map[.unsignedInt(0x04)]?.mapValue {
            for (key, value) in optionsMap {
                if let keyString = key.stringValue, let valueBool = value.boolValue {
                    options[keyString] = valueBool
                }
            }
        }

        // maxMsgSize (0x05) - defaults to 1024
        let maxMsgSize = map[.unsignedInt(0x05)]?.uint64Value.map { UInt($0) } ?? 1024

        // pinUvAuthProtocols (0x06) - defaults to empty array
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
