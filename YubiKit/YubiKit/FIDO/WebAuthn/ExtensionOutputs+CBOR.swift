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

// MARK: - ExtensionOutputs + CBOR

extension ExtensionOutputs: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        // Extract known extensions
        if let credPropsValue = map["credProps"] {
            self.credProps = CredentialPropertiesOutput(cbor: credPropsValue)
        } else {
            self.credProps = nil
        }

        self.largeBlobKey = map["largeBlobKey"]?.dataValue
        self.hmacSecret = map["hmac-secret"]?.boolValue

        if let credProtectValue = map["credProtect"]?.intValue {
            self.credProtect = CredentialProtectionPolicy(rawValue: credProtectValue)
        } else {
            self.credProtect = nil
        }

        self.minPINLength = map["minPINLength"]?.intValue
        self.thirdPartyPayment = map["thirdPartyPayment"]?.boolValue

        // Store unknown extensions
        var other: [String: CBOR.Value] = [:]
        for (key, value) in map {
            guard let keyString = key.stringValue else { continue }

            // Skip known extensions
            if keyString == "credProps"
                || keyString == "largeBlobKey"
                || keyString == "hmac-secret"
                || keyString == "credProtect"
                || keyString == "minPINLength"
                || keyString == "thirdPartyPayment"
            {
                continue
            }

            other[keyString] = value
        }
        self.other = other
    }
}

// MARK: - CredentialPropertiesOutput + CBOR

extension ExtensionOutputs.CredentialPropertiesOutput: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else {
            return nil
        }

        self.rk = map["rk"]?.boolValue
    }
}
