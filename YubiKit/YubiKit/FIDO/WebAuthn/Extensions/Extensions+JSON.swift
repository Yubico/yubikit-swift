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

// MARK: - Extension CodingKey

// Routes every WebAuthn extension JSON key through `Identifier`: the typed
// init requires an Identifier, so new keys can't be added without going
// through the enum.
private struct ExtensionKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init(_ id: WebAuthn.Extension.Identifier, at context: WebAuthn.Extension.Identifier.JSONContext) {
        // nil `jsonKey(at:)` here is a programmer error, not runtime data.
        stringValue = id.jsonKey(at: context)!
    }
    init(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

extension KeyedDecodingContainer where Key == ExtensionKey {
    fileprivate func decodeIfPresent<T: Decodable>(
        _ type: T.Type,
        for identifier: WebAuthn.Extension.Identifier,
        at context: WebAuthn.Extension.Identifier.JSONContext
    ) throws -> T? {
        try decodeIfPresent(type, forKey: .init(identifier, at: context))
    }

    fileprivate func decodeBase64URLIfPresent(
        for identifier: WebAuthn.Extension.Identifier,
        at context: WebAuthn.Extension.Identifier.JSONContext
    ) throws -> Data? {
        try decodeBase64URLIfPresent(forKey: .init(identifier, at: context))
    }
}

extension KeyedEncodingContainer where Key == ExtensionKey {
    fileprivate mutating func encodeIfPresent<T: Encodable>(
        _ value: T?,
        for identifier: WebAuthn.Extension.Identifier,
        at context: WebAuthn.Extension.Identifier.JSONContext
    ) throws {
        try encodeIfPresent(value, forKey: .init(identifier, at: context))
    }

    fileprivate mutating func encode<T: Encodable>(
        _ value: T,
        for identifier: WebAuthn.Extension.Identifier,
        at context: WebAuthn.Extension.Identifier.JSONContext
    ) throws {
        try encode(value, forKey: .init(identifier, at: context))
    }

    fileprivate mutating func encodeBase64URL(
        _ value: Data,
        for identifier: WebAuthn.Extension.Identifier,
        at context: WebAuthn.Extension.Identifier.JSONContext
    ) throws {
        try encodeBase64URL(value, forKey: .init(identifier, at: context))
    }
}

// MARK: - Registration Inputs Decodable

extension WebAuthn.Extension.RegistrationInputs: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: ExtensionKey.self)
        let context = WebAuthn.Extension.Identifier.JSONContext.registrationInput

        // credProtect registration is composite: credentialProtectionPolicy (primary,
        // from Identifier.jsonKey) + enforceCredentialProtectionPolicy (companion).
        let credProtect: WebAuthn.Extension.CredProtect.Registration.Input?
        if let policy = try container.decodeIfPresent(
            WebAuthn.Extension.CredProtect.Policy.self,
            for: .credProtect,
            at: context
        ) {
            // credProtect's sole composite companion; lives inline because it's the only one.
            let enforce =
                try container.decodeIfPresent(
                    Bool.self,
                    forKey: .init(stringValue: "enforceCredentialProtectionPolicy")
                ) ?? false
            credProtect = .init(policy: policy, enforce: enforce)
        } else {
            credProtect = nil
        }

        self.init(
            prf: try container.decodeIfPresent(
                WebAuthn.Extension.PRF.Registration.Input.self,
                for: .prf,
                at: context
            ),
            credProtect: credProtect,
            credBlob: try container.decodeBase64URLIfPresent(for: .credBlob, at: context),
            minPinLength: try container.decodeIfPresent(Bool.self, for: .minPinLength, at: context),
            largeBlob: try container.decodeIfPresent(
                WebAuthn.Extension.LargeBlob.Registration.Input.self,
                for: .largeBlob,
                at: context
            ),
            credProps: try container.decodeIfPresent(Bool.self, for: .credProps, at: context),
            previewSign: try container.decodeIfPresent(
                WebAuthn.Extension.PreviewSign.Registration.Input.self,
                for: .previewSign,
                at: context
            ),
            thirdPartyPayment: try container.decodeIfPresent(
                WebAuthn.Extension.ThirdPartyPayment.Registration.Input.self,
                for: .thirdPartyPayment,
                at: context
            )
        )
    }
}

// MARK: - Authentication Inputs Decodable

extension WebAuthn.Extension.AuthenticationInputs: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: ExtensionKey.self)
        let context = WebAuthn.Extension.Identifier.JSONContext.authenticationInput
        self.init(
            prf: try container.decodeIfPresent(
                WebAuthn.Extension.PRF.Authentication.Input.self,
                for: .prf,
                at: context
            ),
            getCredBlob: try container.decodeIfPresent(Bool.self, for: .credBlob, at: context),
            largeBlob: try container.decodeIfPresent(
                WebAuthn.Extension.LargeBlob.Authentication.Input.self,
                for: .largeBlob,
                at: context
            ),
            previewSign: try container.decodeIfPresent(
                WebAuthn.Extension.PreviewSign.Authentication.Input.self,
                for: .previewSign,
                at: context
            ),
            thirdPartyPayment: try container.decodeIfPresent(
                WebAuthn.Extension.ThirdPartyPayment.Authentication.Input.self,
                for: .thirdPartyPayment,
                at: context
            )
        )
    }
}

// MARK: - Registration Outputs Encodable

extension WebAuthn.Extension.RegistrationOutputs: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: ExtensionKey.self)
        let context = WebAuthn.Extension.Identifier.JSONContext.registrationOutput
        try container.encodeIfPresent(prf, for: .prf, at: context)
        if let credProtect {
            try container.encode(credProtect.policy, for: .credProtect, at: context)
        }
        if let credBlob {
            try container.encode(credBlob.stored, for: .credBlob, at: context)
        }
        if let minPinLength {
            try container.encode(minPinLength.length, for: .minPinLength, at: context)
        }
        try container.encodeIfPresent(largeBlob, for: .largeBlob, at: context)
        try container.encodeIfPresent(credProps, for: .credProps, at: context)
        try container.encodeIfPresent(previewSign, for: .previewSign, at: context)
    }
}

// MARK: - Authentication Outputs Encodable

extension WebAuthn.Extension.AuthenticationOutputs: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: ExtensionKey.self)
        let context = WebAuthn.Extension.Identifier.JSONContext.authenticationOutput
        try container.encodeIfPresent(prf, for: .prf, at: context)
        if let credBlob {
            try container.encodeBase64URL(credBlob.blob, for: .credBlob, at: context)
        }
        try container.encodeIfPresent(largeBlob, for: .largeBlob, at: context)
        try container.encodeIfPresent(previewSign, for: .previewSign, at: context)
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

// MARK: - PreviewSign Registration Input Decodable

extension WebAuthn.Extension.PreviewSign.Registration.Input: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Reject mixed-mode: signByCredential is not allowed during registration
        if container.contains(.signByCredential) {
            throw DecodingError.dataCorruptedError(
                forKey: .signByCredential,
                in: container,
                debugDescription: "signByCredential is not allowed in registration"
            )
        }

        let generateKey = try container.decodeIfPresent(GenerateKeyInput.self, forKey: .generateKey)
        guard let generateKey else {
            throw DecodingError.dataCorruptedError(
                forKey: .generateKey,
                in: container,
                debugDescription: "previewSign registration requires generateKey"
            )
        }
        self.init(algorithms: generateKey.algorithms)
    }

    private struct GenerateKeyInput: Decodable {
        let algorithms: [COSE.Algorithm]

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let rawAlgorithms = try container.decode([Int].self, forKey: .algorithms)
            self.algorithms = rawAlgorithms.map { COSE.Algorithm(rawValue: $0) }
        }

        private enum CodingKeys: String, CodingKey {
            case algorithms
        }
    }

    private enum CodingKeys: String, CodingKey {
        case generateKey, signByCredential
    }
}

// MARK: - PreviewSign Authentication Input Decodable

extension WebAuthn.Extension.PreviewSign.Authentication.Input: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        // Reject mixed-mode: generateKey is not allowed during authentication
        if container.contains(.generateKey) {
            throw DecodingError.dataCorruptedError(
                forKey: .generateKey,
                in: container,
                debugDescription: "generateKey is not allowed in authentication"
            )
        }

        let stringKeyed = try container.decode(
            [String: WebAuthn.Extension.PreviewSign.SigningParams].self,
            forKey: .signByCredential
        )

        var byCredential: [Data: WebAuthn.Extension.PreviewSign.SigningParams] = [:]
        for (key, value) in stringKeyed {
            guard let credId = Data(base64URLEncoded: key) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .signByCredential,
                    in: container,
                    debugDescription: "Invalid base64url credential ID in signByCredential: \(key)"
                )
            }
            byCredential[credId] = value
        }

        self.init(signByCredential: byCredential)
    }

    private enum CodingKeys: String, CodingKey {
        case signByCredential, generateKey
    }
}

// MARK: - PreviewSign SigningParams Decodable

extension WebAuthn.Extension.PreviewSign.SigningParams: Decodable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            keyHandle: try container.decodeBase64URL(forKey: .keyHandle),
            tbs: try container.decodeBase64URL(forKey: .tbs),
            additionalArgs: try container.decodeBase64URLIfPresent(forKey: .additionalArgs)
        )
    }

    private enum CodingKeys: String, CodingKey {
        case keyHandle, tbs, additionalArgs
    }
}

// MARK: - PreviewSign Registration Output Encodable

extension WebAuthn.Extension.PreviewSign.Registration.Output: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(generatedKey, forKey: .generatedKey)
    }

    private enum CodingKeys: String, CodingKey {
        case generatedKey
    }
}

// MARK: - PreviewSign GeneratedKey Encodable

extension CTAP2.Extension.PreviewSign.GeneratedKey: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeBase64URL(keyHandle, forKey: .keyHandle)
        try container.encodeBase64URL(publicKey, forKey: .publicKey)
        try container.encode(algorithm.rawValue, forKey: .algorithm)
        try container.encodeBase64URL(attestationObject, forKey: .attestationObject)
    }

    private enum CodingKeys: String, CodingKey {
        case keyHandle, publicKey, algorithm, attestationObject
    }
}

// MARK: - PreviewSign Authentication Output Encodable

extension WebAuthn.Extension.PreviewSign.Authentication.Output: Encodable {

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeBase64URL(signature, forKey: .signature)
    }

    private enum CodingKeys: String, CodingKey {
        case signature
    }
}

// MARK: - ThirdPartyPayment Codable

extension WebAuthn.Extension.ThirdPartyPayment.Registration.Input: Decodable {
    private enum CodingKeys: String, CodingKey { case isPayment }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // Absent `isPayment` means the RP didn't actually request payment capability
        // — match python-fido2 / yubikit-android, which skip the extension in that case.
        self.init(isPayment: try c.decodeIfPresent(Bool.self, forKey: .isPayment) ?? false)
    }
}

extension WebAuthn.Extension.ThirdPartyPayment.Authentication.Input: Decodable {
    private enum CodingKeys: String, CodingKey { case isPayment }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(isPayment: try c.decodeIfPresent(Bool.self, forKey: .isPayment) ?? false)
    }
}
