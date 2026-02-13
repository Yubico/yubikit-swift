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

// MARK: - Session BioEnrollment Accessor

extension CTAP2.Session {
    /// Returns bio enrollment operations bound to a PIN auth token.
    ///
    /// ```swift
    /// let pinToken = try await session.getPinToken(
    ///     "123456",
    ///     permissions: [.bioEnrollment]
    /// )
    /// let bio = try await session.bioEnrollment(pinToken: pinToken)
    /// let sensor = try await bio.getFingerprintSensorInfo()
    /// ```
    ///
    /// - Parameter pinToken: PIN auth token with `bioEnrollment` permission.
    /// - Returns: BioEnrollment operations bound to the token.
    /// - Throws: `CTAP2.SessionError.featureNotSupported` if bio enrollment is not supported.
    /// - SeeAlso: [CTAP2 authenticatorBioEnrollment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorBioEnrollment)
    public func bioEnrollment(
        pinToken: CTAP2.ClientPin.PinToken
    ) async throws(CTAP2.SessionError) -> CTAP2.BioEnrollment {
        try await makeBioEnrollment(token: pinToken)
    }

    /// Returns bio enrollment operations bound to a UV auth token.
    ///
    /// ```swift
    /// let uvToken = try await session.getUVToken(
    ///     permissions: [.bioEnrollment]
    /// )
    /// let bio = try await session.bioEnrollment(uvToken: uvToken)
    /// let sensor = try await bio.getFingerprintSensorInfo()
    /// ```
    ///
    /// - Parameter uvToken: UV auth token with `bioEnrollment` permission.
    /// - Returns: BioEnrollment operations bound to the token.
    /// - Throws: `CTAP2.SessionError.featureNotSupported` if bio enrollment is not supported.
    /// - SeeAlso: [CTAP2 authenticatorBioEnrollment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorBioEnrollment)
    public func bioEnrollment(
        uvToken: CTAP2.ClientPin.UVToken
    ) async throws(CTAP2.SessionError) -> CTAP2.BioEnrollment {
        try await makeBioEnrollment(token: uvToken)
    }

    /// Returns bio enrollment operations bound to a PIN/UV auth token.
    ///
    /// - Deprecated: Use ``bioEnrollment(pinToken:)`` (PinToken) or ``bioEnrollment(uvToken:)`` instead.
    @available(*, deprecated, message: "Use bioEnrollment(pinToken: PinToken) or bioEnrollment(uvToken:)")
    public func bioEnrollment(
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) -> CTAP2.BioEnrollment {
        try await makeBioEnrollment(token: pinToken)
    }

    private func makeBioEnrollment(
        token: any CTAP2.ClientPin.PinUVAuthToken
    ) async throws(CTAP2.SessionError) -> CTAP2.BioEnrollment {
        guard try await CTAP2.BioEnrollment.isSupported(by: self) else {
            throw .featureNotSupported(source: .here())
        }
        let modality = try await CTAP2.BioEnrollment.getModality(for: self)
        guard modality == .fingerprint else {
            throw .featureNotSupported(source: .here())
        }
        let command = try await CTAP2.BioEnrollment.commandCode(for: self)
        return CTAP2.BioEnrollment(session: self, token: token, command: command)
    }
}

// MARK: - BioEnrollment

extension CTAP2 {
    /// Bio enrollment operations bound to a PIN/UV auth token.
    ///
    /// Allows managing fingerprint enrollments on biometric authenticators (e.g., YubiKey Bio).
    ///
    /// - SeeAlso: [CTAP2 authenticatorBioEnrollment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorBioEnrollment)
    public struct BioEnrollment: Sendable {
        private let session: CTAP2.Session
        private let token: any CTAP2.ClientPin.PinUVAuthToken
        private let command: CTAP2.Command

        fileprivate init(session: CTAP2.Session, token: any CTAP2.ClientPin.PinUVAuthToken, command: CTAP2.Command) {
            self.session = session
            self.token = token
            self.command = command
        }

        // MARK: - Feature Detection

        /// Checks if the authenticator supports bio enrollment.
        public static func isSupported(by session: CTAP2.Session) async throws(CTAP2.SessionError) -> Bool {
            let info = try await session.cachedInfo
            return info.options.supportsBioEnroll
                || (info.versions.contains(.fido2_1Pre)
                    && info.options.supportsUserVerificationMgmtPreview)
        }

        /// Gets the bio modality supported by the authenticator.
        ///
        /// - SeeAlso: [Get bio modality](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#getUserVerificationModality)
        public static func getModality(
            for session: CTAP2.Session
        ) async throws(CTAP2.SessionError) -> Modality {
            let command = try await commandCode(for: session)
            let response: GetModalityResponse = try await session.interface.send(
                command: command,
                payload: getModalityRequest
            ).value
            return response.modality
        }

        // MARK: - Operations

        /// Gets fingerprint sensor information.
        ///
        /// - SeeAlso: [Get fingerprint sensor info](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#getFingerprintSensorInfo)
        public func getFingerprintSensorInfo() async throws(CTAP2.SessionError) -> FingerprintSensorInfo {
            try await executeNoAuth(subcommand: .getFingerprintSensorInfo)
        }

        // MARK: - Enrollment

        /// Begins a new fingerprint enrollment and returns an async sequence of samples.
        ///
        /// Use this for a simplified enrollment loop:
        /// ```swift
        /// for try await sample in bio.enroll(timeout: 10000) {
        ///     switch sample {
        ///     case .waitingForUser:
        ///         print("Touch the fingerprint sensor...")
        ///     case .sample(let status, let remaining):
        ///         print("Status: \(status), \(remaining) remaining")
        ///     case .completed(let templateId, let status):
        ///         print("Enrollment complete: \(templateId), status: \(status)")
        ///     }
        /// }
        /// ```
        ///
        /// - Parameter timeout: Optional timeout in milliseconds for each fingerprint capture.
        /// - Returns: An async sequence that yields samples until enrollment is complete.
        /// - SeeAlso: [Enrolling Fingerprint](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#enrollingFingerprint)
        public func enroll(timeout: UInt? = nil) -> EnrollFingerprint {
            EnrollFingerprint(bioEnrollment: self, timeout: timeout)
        }

        fileprivate func enrollBegin(
            timeout: UInt? = nil
        ) async -> CTAP2.StatusStream<EnrollBeginResult> {
            var params: [UInt8: CBOR.Value]?
            if let timeout {
                params = [SubcommandParam.timeoutMilliseconds.rawValue: timeout.cbor()]
            }
            return await executeStream(subcommand: .enrollBegin, params: params)
        }

        fileprivate func enrollCaptureNext(
            templateId: Data,
            timeout: UInt? = nil
        ) async -> CTAP2.StatusStream<CaptureResult> {
            var params: [UInt8: CBOR.Value] = [
                SubcommandParam.templateId.rawValue: templateId.cbor()
            ]
            if let timeout {
                params[SubcommandParam.timeoutMilliseconds.rawValue] = timeout.cbor()
            }
            return await executeStream(subcommand: .enrollCaptureNextSample, params: params)
        }

        /// Cancels the current enrollment.
        ///
        /// - SeeAlso: [Cancel Current Enrollment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#cancelCurrentEnrollment)
        public func cancelEnrollment() async throws(CTAP2.SessionError) {
            try await executeNoAuth(subcommand: .cancelCurrentEnrollment) as Void
        }

        /// An async sequence of enrolled fingerprint templates.
        ///
        /// - SeeAlso: [Enumerate Enrollments](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#enumerateEnrollments)
        public var enrollments: EnrollmentSequence {
            EnrollmentSequence(bioEnrollment: self)
        }

        /// Sets a friendly name for a fingerprint template.
        ///
        /// - Parameters:
        ///   - name: The friendly name to set (e.g., "Right Index").
        ///   - templateId: The template to rename.
        /// - SeeAlso: [Set Friendly Name](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#setFriendlyName)
        public func setFriendlyName(
            _ name: String,
            for templateId: Data
        ) async throws(CTAP2.SessionError) {
            let params: [UInt8: CBOR.Value] = [
                SubcommandParam.templateId.rawValue: templateId.cbor(),
                SubcommandParam.templateFriendlyName.rawValue: name.cbor(),
            ]
            try await execute(subcommand: .setFriendlyName, params: params) as Void
        }

        /// Removes a fingerprint enrollment.
        ///
        /// - Parameter templateId: The template to remove.
        /// - SeeAlso: [Remove Enrollment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#removeEnrollment)
        public func removeEnrollment(
            _ templateId: Data
        ) async throws(CTAP2.SessionError) {
            let params: [UInt8: CBOR.Value] = [
                SubcommandParam.templateId.rawValue: templateId.cbor()
            ]
            try await execute(subcommand: .removeEnrollment, params: params) as Void
        }

        // MARK: - Internal

        fileprivate func fetchEnrollments() async throws(CTAP2.SessionError) -> [TemplateInfo] {
            do {
                let response: EnumerateEnrollmentsResponse =
                    try await execute(subcommand: .enumerateEnrollments)
                return response.templateInfos
            } catch .ctapError(.invalidOption, _), .ctapError(.noCredentials, _) {
                return []
            }
        }

        fileprivate static func commandCode(
            for session: CTAP2.Session
        ) async throws(CTAP2.SessionError) -> CTAP2.Command {
            let info = try await session.cachedInfo
            return info.options.supportsBioEnroll ? .bioEnrollment : .bioEnrollmentPreview
        }

        private func execute<R: CBOR.Decodable & Sendable>(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]? = nil
        ) async throws(CTAP2.SessionError) -> R {
            let parameters = authParameters(subcommand: subcommand, params: params)
            return try await session.interface.send(command: command, payload: parameters).value
        }

        private func execute(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]? = nil
        ) async throws(CTAP2.SessionError) {
            let parameters = authParameters(subcommand: subcommand, params: params)
            try await session.interface.send(command: command, payload: parameters).value
        }

        private func executeStream<R: CBOR.Decodable & Sendable>(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]? = nil
        ) async -> CTAP2.StatusStream<R> {
            let parameters = authParameters(subcommand: subcommand, params: params)
            return await session.interface.send(command: command, payload: parameters)
        }

        private func executeNoAuth<R: CBOR.Decodable & Sendable>(
            subcommand: Subcommand
        ) async throws(CTAP2.SessionError) -> R {
            try await session.interface.send(
                command: command,
                payload: RequestParametersNoAuth(subCommand: subcommand)
            ).value
        }

        private func executeNoAuth(
            subcommand: Subcommand
        ) async throws(CTAP2.SessionError) {
            try await session.interface.send(
                command: command,
                payload: RequestParametersNoAuth(subCommand: subcommand)
            ).value
        }

        private func authParameters(
            subcommand: Subcommand,
            params: [UInt8: CBOR.Value]?
        ) -> RequestParameters {
            // Auth message format: modality(0x01) || subCommand || CBOR(params)
            var message = Data([Modality.fingerprint.rawValue, subcommand.rawValue])
            if let params {
                message.append(params.cbor().encode())
            }
            return RequestParameters(
                modality: .fingerprint,
                subCommand: subcommand,
                subCommandParams: params,
                pinUVAuthProtocol: token.protocolVersion,
                pinUVAuthParam: token.authenticate(message: message)
            )
        }
    }
}

// MARK: - Internal Types

extension CTAP2.BioEnrollment {
    /// Bio modality supported by the authenticator.
    public enum Modality: UInt8, Sendable {
        case fingerprint = 0x01
    }

    enum Subcommand: UInt8, Sendable {
        case enrollBegin = 0x01
        case enrollCaptureNextSample = 0x02
        case cancelCurrentEnrollment = 0x03
        case enumerateEnrollments = 0x04
        case setFriendlyName = 0x05
        case removeEnrollment = 0x06
        case getFingerprintSensorInfo = 0x07
    }

    enum SubcommandParam: UInt8, Sendable {
        case templateId = 0x01
        case templateFriendlyName = 0x02
        case timeoutMilliseconds = 0x03
    }

    struct RequestParameters: Sendable, CBOR.Encodable {
        let modality: Modality
        let subCommand: Subcommand
        let subCommandParams: [UInt8: CBOR.Value]?
        let pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion
        let pinUVAuthParam: Data

        func cbor() -> CBOR.Value {
            var map: [CBOR.Value: CBOR.Value] = [:]
            map[.int(0x01)] = .int(Int(modality.rawValue))
            map[.int(0x02)] = .int(Int(subCommand.rawValue))
            if let params = subCommandParams, !params.isEmpty {
                var paramsMap: [CBOR.Value: CBOR.Value] = [:]
                for (key, value) in params {
                    paramsMap[.int(Int(key))] = value
                }
                map[.int(0x03)] = .map(paramsMap)
            }
            map[.int(0x04)] = pinUVAuthProtocol.cbor()
            map[.int(0x05)] = pinUVAuthParam.cbor()
            return .map(map)
        }
    }

    struct RequestParametersNoAuth: Sendable, CBOR.Encodable {
        let subCommand: Subcommand

        func cbor() -> CBOR.Value {
            let map: [CBOR.Value: CBOR.Value] = [
                .int(0x01): .int(Int(Modality.fingerprint.rawValue)),
                .int(0x02): .int(Int(subCommand.rawValue)),
            ]
            return .map(map)
        }
    }

    static let getModalityRequest: CBOR.Value = .map([.int(0x06): .boolean(true)])
}

// MARK: - Enrollment AsyncSequence

extension CTAP2.BioEnrollment {

    /// A sample captured during fingerprint enrollment.
    public enum EnrollmentSample: Sendable {
        /// The authenticator is waiting for a finger touch.
        case waitingForUser
        /// A sample was captured (good or bad).
        case sample(status: SampleStatus, remaining: UInt)
        /// Enrollment completed successfully.
        case completed(templateId: Data, status: SampleStatus)
    }

    /// An async sequence that yields enrollment samples until complete.
    public struct EnrollFingerprint: AsyncSequence, Sendable {
        public typealias Element = EnrollmentSample

        private let stream: AsyncThrowingStream<EnrollmentSample, any Error>

        fileprivate init(bioEnrollment: CTAP2.BioEnrollment, timeout: UInt?) {
            self.stream = AsyncThrowingStream { continuation in
                let task = Task {
                    do {
                        try await Self.run(
                            bioEnrollment: bioEnrollment,
                            timeout: timeout,
                            continuation: continuation
                        )
                    } catch {
                        continuation.finish(throwing: error)
                    }
                }
                continuation.onTermination = { termination in
                    task.cancel()
                    if case .cancelled = termination {
                        Task { try? await bioEnrollment.cancelEnrollment() }
                    }
                }
            }
        }

        private static func run(
            bioEnrollment: CTAP2.BioEnrollment,
            timeout: UInt?,
            continuation: AsyncThrowingStream<EnrollmentSample, any Error>.Continuation
        ) async throws {
            // First capture - enrollBegin
            var templateId: Data?
            for try await status in await bioEnrollment.enrollBegin(timeout: timeout) {
                switch status {
                case .processing:
                    break
                case .waitingForUser:
                    continuation.yield(.waitingForUser)
                case .finished(let result):
                    templateId = result.templateId
                    if result.remainingSamples == 0 {
                        continuation.yield(
                            .completed(
                                templateId: result.templateId,
                                status: result.sampleStatus
                            )
                        )
                        continuation.finish()
                        return
                    }
                    continuation.yield(
                        .sample(
                            status: result.sampleStatus,
                            remaining: result.remainingSamples
                        )
                    )
                }
            }

            guard let templateId else {
                continuation.finish()
                return
            }

            // Subsequent captures - enrollCaptureNext
            while !Task.isCancelled {
                let stream = await bioEnrollment.enrollCaptureNext(
                    templateId: templateId,
                    timeout: timeout
                )
                for try await status in stream {
                    switch status {
                    case .processing:
                        break
                    case .waitingForUser:
                        continuation.yield(.waitingForUser)
                    case .finished(let result):
                        if result.remainingSamples == 0 {
                            continuation.yield(
                                .completed(
                                    templateId: templateId,
                                    status: result.sampleStatus
                                )
                            )
                            continuation.finish()
                            return
                        }
                        continuation.yield(
                            .sample(
                                status: result.sampleStatus,
                                remaining: result.remainingSamples
                            )
                        )
                    }
                }
            }
        }

        public func makeAsyncIterator() -> AsyncThrowingStream<EnrollmentSample, any Error>.AsyncIterator {
            stream.makeAsyncIterator()
        }
    }

    // AsyncSequence conformance matches RPSequence/CredentialSequence API shape,
    // though enumerateEnrollments returns all templates in a single response (no pagination).
    public struct EnrollmentSequence: AsyncSequence, Sendable {
        public typealias Element = TemplateInfo

        fileprivate let bioEnrollment: CTAP2.BioEnrollment

        /// Collects all enrolled templates into an array.
        public func enumerate() async throws(CTAP2.SessionError) -> [TemplateInfo] {
            try await bioEnrollment.fetchEnrollments()
        }

        public func makeAsyncIterator() -> Iterator {
            Iterator(bioEnrollment: bioEnrollment)
        }

        public struct Iterator: AsyncIteratorProtocol {
            private let bioEnrollment: CTAP2.BioEnrollment
            private var items: [TemplateInfo]?
            private var index = 0

            fileprivate init(bioEnrollment: CTAP2.BioEnrollment) {
                self.bioEnrollment = bioEnrollment
            }

            public mutating func next() async throws(CTAP2.SessionError) -> TemplateInfo? {
                if items == nil { items = try await bioEnrollment.fetchEnrollments() }
                guard let items, index < items.count else { return nil }
                defer { index += 1 }
                return items[index]
            }
        }
    }
}
