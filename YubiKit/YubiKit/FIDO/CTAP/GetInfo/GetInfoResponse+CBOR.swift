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

extension CTAP2.GetInfo.Response: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Required: versions (0x01) - array of strings
        guard let versions: [String] = map[.int(0x01)]?.cborDecoded(),
            !versions.isEmpty
        else {
            return nil
        }

        // Required: aaguid (0x03) - 16-byte byte string
        guard let aaguid: Data = map[.int(0x03)]?.cborDecoded(),
            aaguid.count == 16
        else {
            return nil
        }

        self.init(
            versions: versions,
            aaguid: aaguid,
            extensions: map[.int(0x02)]?.cborDecoded() ?? [],
            options: map[.int(0x04)]?.cborDecoded() ?? [:],
            maxMsgSize: map[.int(0x05)]?.cborDecoded() ?? 1024,
            pinUVAuthProtocols: map[.int(0x06)]?.cborDecoded() ?? [],
            maxCredentialCountInList: map[.int(0x07)]?.cborDecoded(),
            maxCredentialIdLength: map[.int(0x08)]?.cborDecoded(),
            transports: map[.int(0x09)]?.cborDecoded(),
            algorithms: map[.int(0x0A)]?.cborDecoded(),
            maxSerializedLargeBlobArray: map[.int(0x0B)]?.cborDecoded(),
            forcePinChange: map[.int(0x0C)]?.cborDecoded(),
            minPinLength: map[.int(0x0D)]?.cborDecoded(),
            firmwareVersion: map[.int(0x0E)]?.cborDecoded(),
            maxCredBlobLength: map[.int(0x0F)]?.cborDecoded(),
            maxRPIDsForSetMinPinLength: map[.int(0x10)]?.cborDecoded(),
            preferredPlatformUVAttempts: map[.int(0x11)]?.cborDecoded(),
            uvModality: map[.int(0x12)]?.cborDecoded(),
            certifications: map[.int(0x13)]?.cborDecoded(),
            remainingDiscoverableCredentials: map[.int(0x14)]?.cborDecoded(),
            vendorPrototypeConfigCommands: map[.int(0x15)]?.cborDecoded()
        )
    }
}
