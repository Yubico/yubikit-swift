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

// MARK: - Registration Inputs Decodable

extension WebAuthn.Extension.RegistrationInputs: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Parse credProtect from credentialProtectionPolicy + enforceCredentialProtectionPolicy
        let credProtect: WebAuthn.Extension.CredProtect.Registration.Input?
        if let policy = try container.decodeIfPresent(
            WebAuthn.Extension.CredProtect.Policy.self,
            forKey: .credentialProtectionPolicy
        ) {
            let enforce = try container.decodeIfPresent(Bool.self, forKey: .enforceCredentialProtectionPolicy) ?? false
            credProtect = .init(policy: policy, enforce: enforce)
        } else {
            credProtect = nil
        }

        self.init(
            prf: try container.decodeIfPresent(WebAuthn.Extension.PRF.Registration.Input.self, forKey: .prf),
            credProtect: credProtect,
            credBlob: try container.decodeBase64URLIfPresent(forKey: .credBlob),
            minPinLength: try container.decodeIfPresent(Bool.self, forKey: .minPinLength),
            largeBlob: try container.decodeIfPresent(
                WebAuthn.Extension.LargeBlob.Registration.Input.self,
                forKey: .largeBlob
            ),
            credProps: try container.decodeIfPresent(Bool.self, forKey: .credProps)
        )
    }

    private enum CodingKeys: String, CodingKey {
        case prf, credentialProtectionPolicy, enforceCredentialProtectionPolicy, credBlob, minPinLength, largeBlob
        case credProps
    }
}

// MARK: - Authentication Inputs Decodable

extension WebAuthn.Extension.AuthenticationInputs: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            prf: try container.decodeIfPresent(WebAuthn.Extension.PRF.Authentication.Input.self, forKey: .prf),
            getCredBlob: try container.decodeIfPresent(Bool.self, forKey: .getCredBlob),
            largeBlob: try container.decodeIfPresent(
                WebAuthn.Extension.LargeBlob.Authentication.Input.self,
                forKey: .largeBlob
            )
        )
    }

    private enum CodingKeys: String, CodingKey {
        case prf, getCredBlob, largeBlob
    }
}

// MARK: - Registration Outputs Encodable

extension WebAuthn.Extension.RegistrationOutputs: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(prf, forKey: .prf)
        if let credProtect {
            try container.encode(credProtect.policy, forKey: .credProtect)
        }
        if let credBlob {
            try container.encode(credBlob.stored, forKey: .credBlob)
        }
        if let minPinLength {
            try container.encode(minPinLength.length, forKey: .minPinLength)
        }
        try container.encodeIfPresent(largeBlob, forKey: .largeBlob)
        try container.encodeIfPresent(credProps, forKey: .credProps)
    }

    private enum CodingKeys: String, CodingKey {
        case prf, credProtect, credBlob, minPinLength, largeBlob, credProps
    }
}

// MARK: - Authentication Outputs Encodable

extension WebAuthn.Extension.AuthenticationOutputs: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(prf, forKey: .prf)
        if let credBlob {
            try container.encodeBase64URL(credBlob.blob, forKey: .getCredBlob)
        }
        try container.encodeIfPresent(largeBlob, forKey: .largeBlob)
    }

    private enum CodingKeys: String, CodingKey {
        case prf, getCredBlob, largeBlob
    }
}

// MARK: - PRF Registration Input Decodable

extension WebAuthn.Extension.PRF.Registration.Input: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let eval = try container.decodeIfPresent(WebAuthn.Extension.PRF.Eval.self, forKey: .eval)
        self.init(eval: eval)
    }

    private enum CodingKeys: String, CodingKey {
        case eval
    }
}

// MARK: - PRF Authentication Input Decodable

extension WebAuthn.Extension.PRF.Authentication.Input: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let eval = try container.decodeIfPresent(WebAuthn.Extension.PRF.Eval.self, forKey: .eval)

        // evalByCredential uses base64url credential IDs as string keys
        var byCredential: [Data: WebAuthn.Extension.PRF.Eval] = [:]
        if let stringKeyed = try container.decodeIfPresent(
            [String: WebAuthn.Extension.PRF.Eval].self,
            forKey: .evalByCredential
        ) {
            for (key, value) in stringKeyed {
                guard let credId = Data(base64URLEncoded: key) else {
                    throw DecodingError.dataCorruptedError(
                        forKey: .evalByCredential,
                        in: container,
                        debugDescription: "Invalid base64url credential ID in evalByCredential: \(key)"
                    )
                }
                byCredential[credId] = value
            }
        }

        self.init(eval: eval, evalByCredential: byCredential)
    }

    private enum CodingKeys: String, CodingKey {
        case eval, evalByCredential
    }
}

// MARK: - PRF Eval Codable

extension WebAuthn.Extension.PRF.Eval: Codable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            first: try container.decodeBase64URL(forKey: .first),
            second: try container.decodeBase64URLIfPresent(forKey: .second)
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeBase64URL(first, forKey: .first)
        try container.encodeBase64URLIfPresent(second, forKey: .second)
    }

    private enum CodingKeys: String, CodingKey {
        case first, second
    }
}

// MARK: - PRF Registration Output Encodable

extension WebAuthn.Extension.PRF.Registration.Output: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(enabled, forKey: .enabled)
        try container.encodeIfPresent(results, forKey: .results)
    }

    private enum CodingKeys: String, CodingKey {
        case enabled, results
    }
}

// MARK: - PRF Authentication Output Encodable

extension WebAuthn.Extension.PRF.Authentication.Output: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(results, forKey: .results)
    }

    private enum CodingKeys: String, CodingKey {
        case results
    }
}

// MARK: - PRF Results Encodable

extension WebAuthn.Extension.PRF.Results: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeBase64URL(first, forKey: .first)
        try container.encodeBase64URLIfPresent(second, forKey: .second)
    }

    private enum CodingKeys: String, CodingKey {
        case first, second
    }
}

// MARK: - Credential Protection Policy Codable

extension CTAP2.Extension.CredProtect.Level: Codable {

    /// WebAuthn JSON string values for credentialProtectionPolicy.
    private var stringValue: String {
        switch self {
        case .userVerificationOptional:
            return "userVerificationOptional"
        case .userVerificationOptionalWithCredentialIDList:
            return "userVerificationOptionalWithCredentialIDList"
        case .userVerificationRequired:
            return "userVerificationRequired"
        }
    }

    private init?(stringValue: String) {
        switch stringValue {
        case "userVerificationOptional":
            self = .userVerificationOptional
        case "userVerificationOptionalWithCredentialIDList":
            self = .userVerificationOptionalWithCredentialIDList
        case "userVerificationRequired":
            self = .userVerificationRequired
        default:
            return nil
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringValue = try container.decode(String.self)
        guard let level = Self(stringValue: stringValue) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid credentialProtectionPolicy: \(stringValue)"
            )
        }
        self = level
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(stringValue)
    }
}

// MARK: - LargeBlob Support Codable

extension WebAuthn.Extension.LargeBlob.Support: Codable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        guard let value = Self(rawValue: rawValue) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid largeBlob support value: \(rawValue)"
            )
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

// MARK: - LargeBlob Registration Input Decodable

extension WebAuthn.Extension.LargeBlob.Registration.Input: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            support: try container.decode(WebAuthn.Extension.LargeBlob.Support.self, forKey: .support)
        )
    }

    private enum CodingKeys: String, CodingKey {
        case support
    }
}

// MARK: - LargeBlob Registration Output Encodable

extension WebAuthn.Extension.LargeBlob.Registration.Output: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(supported, forKey: .supported)
    }

    private enum CodingKeys: String, CodingKey {
        case supported
    }
}

// MARK: - LargeBlob Authentication Input Decodable

extension WebAuthn.Extension.LargeBlob.Authentication.Input: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let hasRead = try container.decodeIfPresent(Bool.self, forKey: .read) == true
        let writeData = try container.decodeBase64URLIfPresent(forKey: .write)

        if hasRead && writeData != nil {
            throw DecodingError.dataCorruptedError(
                forKey: CodingKeys.read,
                in: container,
                debugDescription: "largeBlob 'read' and 'write' are mutually exclusive"
            )
        }

        if let writeData {
            self = .write(writeData)
        } else if hasRead {
            self = .read
        } else {
            throw DecodingError.dataCorruptedError(
                forKey: CodingKeys.read,
                in: container,
                debugDescription: "largeBlob requires either 'read' or 'write'"
            )
        }
    }

    private enum CodingKeys: String, CodingKey {
        case read, write
    }
}

// MARK: - LargeBlob Authentication Output Encodable

extension WebAuthn.Extension.LargeBlob.Authentication.Output: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeBase64URLIfPresent(blob, forKey: .blob)
        try container.encodeIfPresent(written, forKey: .written)
    }

    private enum CodingKeys: String, CodingKey {
        case blob, written
    }
}

// MARK: - CredProps Registration Output Encodable

extension WebAuthn.Extension.CredProps.Registration.Output: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rk, forKey: .rk)
    }

    private enum CodingKeys: String, CodingKey {
        case rk
    }
}
