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
        self.init(
            prf: try container.decodeIfPresent(WebAuthn.Extension.PRF.RegistrationInput.self, forKey: .prf),
            credentialProtectionPolicy: try container.decodeIfPresent(
                WebAuthn.Extension.CredentialProtectionPolicy.self,
                forKey: .credentialProtectionPolicy
            ),
            enforceCredentialProtectionPolicy: try container.decodeIfPresent(
                Bool.self,
                forKey: .enforceCredentialProtectionPolicy
            ) ?? false,
            credBlob: try container.decodeBase64URLIfPresent(forKey: .credBlob),
            minPinLength: try container.decodeIfPresent(Bool.self, forKey: .minPinLength) ?? false,
            largeBlob: try container.decodeIfPresent(
                WebAuthn.Extension.LargeBlob.RegistrationInput.self,
                forKey: .largeBlob
            )
        )
    }

    private enum CodingKeys: String, CodingKey {
        case prf, credentialProtectionPolicy, enforceCredentialProtectionPolicy, credBlob, minPinLength, largeBlob
    }
}

// MARK: - Authentication Inputs Decodable

extension WebAuthn.Extension.AuthenticationInputs: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            prf: try container.decodeIfPresent(WebAuthn.Extension.PRF.AuthenticationInput.self, forKey: .prf),
            getCredBlob: try container.decodeIfPresent(Bool.self, forKey: .getCredBlob) ?? false,
            largeBlob: try container.decodeIfPresent(
                WebAuthn.Extension.LargeBlob.AuthenticationInput.self,
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
        try container.encodeIfPresent(credentialProtectionPolicy, forKey: .credProtect)
        try container.encodeIfPresent(credBlobSet, forKey: .credBlob)
        try container.encodeIfPresent(minPinLength, forKey: .minPinLength)
        try container.encodeIfPresent(largeBlob, forKey: .largeBlob)
    }

    private enum CodingKeys: String, CodingKey {
        case prf, credProtect, credBlob, minPinLength, largeBlob
    }
}

// MARK: - Authentication Outputs Encodable

extension WebAuthn.Extension.AuthenticationOutputs: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        if let prf {
            try container.encode(PRFAuthenticationOutputJSON(results: prf), forKey: .prf)
        }
        try container.encodeBase64URLIfPresent(credBlob, forKey: .getCredBlob)
        try container.encodeIfPresent(largeBlob, forKey: .largeBlob)
    }

    private enum CodingKeys: String, CodingKey {
        case prf, getCredBlob, largeBlob
    }
}

// MARK: - PRF Registration Input Decodable

extension WebAuthn.Extension.PRF.RegistrationInput: Decodable {

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

extension WebAuthn.Extension.PRF.AuthenticationInput: Decodable {

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

// MARK: - PRF Registration Output (CTAP type) Encodable

extension CTAP2.Extension.HmacSecret.MakeCredentialOperations.Result: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(true, forKey: .enabled)
        switch self {
        case .enabled:
            break
        case .secrets(let secrets):
            try container.encode(secrets, forKey: .results)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case enabled, results
    }
}

// MARK: - PRF Results (CTAP type) Encodable

extension CTAP2.Extension.HmacSecret.Secrets: Encodable {

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

// MARK: - Private JSON Helpers

/// Wrapper for PRF authentication output to match WebAuthn JSON format.
private struct PRFAuthenticationOutputJSON: Encodable {
    let results: CTAP2.Extension.HmacSecret.Secrets
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

extension WebAuthn.Extension.LargeBlob.RegistrationInput: Decodable {

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

extension WebAuthn.Extension.LargeBlob.RegistrationOutput: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(supported, forKey: .supported)
    }

    private enum CodingKeys: String, CodingKey {
        case supported
    }
}

// MARK: - LargeBlob Authentication Input Decodable

extension WebAuthn.Extension.LargeBlob.AuthenticationInput: Decodable {

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

extension WebAuthn.Extension.LargeBlob.AuthenticationOutput: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeBase64URLIfPresent(blob, forKey: .blob)
        try container.encodeIfPresent(written, forKey: .written)
    }

    private enum CodingKeys: String, CodingKey {
        case blob, written
    }
}
