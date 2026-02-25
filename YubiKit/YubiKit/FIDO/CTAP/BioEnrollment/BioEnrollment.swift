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
    /// Returns bio enrollment operations bound to a PIN/UV auth token.
    ///
    /// ```swift
    /// let token = try await session.getPinUVToken(
    ///     using: .pin("123456"),
    ///     permissions: [.bioEnrollment]
    /// )
    /// let bio = try await session.bioEnrollment(token: token)
    /// let sensor = try await bio.getFingerprintSensorInfo()
    /// ```
    ///
    /// - Parameter token: PIN/UV auth token with `bioEnrollment` permission.
    /// - Returns: BioEnrollment operations bound to the token.
    /// - Throws: `CTAP2.SessionError.featureNotSupported` if bio enrollment is not supported.
    /// - SeeAlso: [CTAP2 authenticatorBioEnrollment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#authenticatorBioEnrollment)
    public func bioEnrollment(
        token: CTAP2.Token
    ) async throws(CTAP2.SessionError) -> CTAP2.BioEnrollment {
        guard try await CTAP2.BioEnrollment.isSupported(by: self) else {
            throw .featureNotSupported(source: .here())
        }
        let command = try await CTAP2.BioEnrollment.commandCode(for: self)
        try await CTAP2.BioEnrollment.verifyFingerprintModality(session: self, command: command)
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
        private let token: CTAP2.Token
        private let command: CTAP2.Command

        fileprivate init(
            session: CTAP2.Session,
            token: CTAP2.Token,
            command: CTAP2.Command
        ) {
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

        // MARK: - Sensor Info

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

        /// Cancels the current enrollment.
        ///
        /// - SeeAlso: [Cancel Current Enrollment](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#cancelCurrentEnrollment)
        public func cancelEnrollment() async throws(CTAP2.SessionError) {
            try await executeNoAuth(subcommand: .cancelCurrentEnrollment) as Void
        }

        // MARK: - Template Management

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

        // MARK: - Private Helpers

        fileprivate static func commandCode(
            for session: CTAP2.Session
        ) async throws(CTAP2.SessionError) -> CTAP2.Command {
            let info = try await session.cachedInfo
            return info.options.supportsBioEnroll ? .bioEnrollment : .bioEnrollmentPreview
        }

        fileprivate static func verifyFingerprintModality(
            session: CTAP2.Session,
            command: CTAP2.Command
        ) async throws(CTAP2.SessionError) {
            let request: CBOR.Value = .map([.int(0x06): .boolean(true)])  // getModality
            let response: CBOR.Value = try await session.interface.send(
                command: command,
                payload: request
            ).value
            let modality = response.mapValue?[.int(0x01)]?.uint64Value
            guard modality == 0x01 else {  // fingerprint
                throw .featureNotSupported(source: .here())
            }
        }

        private func enrollBegin(
            timeout: UInt? = nil
        ) async -> CTAP2.StatusStream<EnrollBeginResult> {
            var params: [UInt8: CBOR.Value]?
            if let timeout {
                params = [SubcommandParam.timeoutMilliseconds.rawValue: timeout.cbor()]
            }
            return await executeStream(subcommand: .enrollBegin, params: params)
        }

        private func enrollCaptureNext(
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

        private func fetchEnrollments() async throws(CTAP2.SessionError) -> [TemplateInfo] {
            do {
                let response: EnumerateEnrollmentsResponse =
                    try await execute(subcommand: .enumerateEnrollments)
                return response.templateInfos
            } catch .ctapError(.invalidOption, _) {
                return []
            }
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
            // Auth message: modality (0x01 = fingerprint) || subCommand || CBOR(params)
            var message = Data([0x01, subcommand.rawValue])
            if let params {
                message.append(params.cbor().encode())
            }
            return RequestParameters(
                subCommand: subcommand,
                subCommandParams: params,
                pinUVAuthProtocol: token.protocolVersion,
                pinUVAuthParam: token.authenticate(message: message)
            )
        }
    }
}

// MARK: - EnrollFingerprint

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

        public func makeAsyncIterator() -> Iterator {
            Iterator(stream.makeAsyncIterator())
        }

        public struct Iterator: AsyncIteratorProtocol {
            private var iterator:
                AsyncStream<
                    Result<EnrollmentSample, CTAP2.SessionError>
                >.AsyncIterator

            fileprivate init(
                _ iterator: AsyncStream<Result<EnrollmentSample, CTAP2.SessionError>>.AsyncIterator
            ) {
                self.iterator = iterator
            }

            public mutating func next() async throws(CTAP2.SessionError) -> EnrollmentSample? {
                guard let result = await iterator.next() else { return nil }
                switch result {
                case .success(let sample): return sample
                case .failure(let error): throw error
                }
            }
        }

        fileprivate init(bioEnrollment: CTAP2.BioEnrollment, timeout: UInt?) {
            self.stream = AsyncStream { continuation in
                let task = Task {
                    await Self.run(
                        bioEnrollment: bioEnrollment,
                        timeout: timeout,
                        continuation: continuation
                    )
                }
                continuation.onTermination = { termination in
                    if case .cancelled = termination {
                        task.cancel()
                    }
                }
            }
        }

        private let stream: AsyncStream<Result<EnrollmentSample, CTAP2.SessionError>>

        private static func run(
            bioEnrollment: CTAP2.BioEnrollment,
            timeout: UInt?,
            continuation: AsyncStream<Result<EnrollmentSample, CTAP2.SessionError>>.Continuation
        ) async {
            var completed = false
            do {
                completed = try await runEnrollment(
                    bioEnrollment: bioEnrollment,
                    timeout: timeout,
                    continuation: continuation
                )
            } catch {
                continuation.yield(.failure(error))
            }
            continuation.finish()
            if !completed {
                try? await bioEnrollment.cancelEnrollment()
            }
        }

        /// Returns `true` when enrollment completed successfully, `false` if interrupted or cancelled.
        private static func runEnrollment(
            bioEnrollment: CTAP2.BioEnrollment,
            timeout: UInt?,
            continuation: AsyncStream<Result<EnrollmentSample, CTAP2.SessionError>>.Continuation
        ) async throws(CTAP2.SessionError) -> Bool {
            // First capture - enrollBegin
            var templateId: Data?
            for try await status in await bioEnrollment.enrollBegin(timeout: timeout) {
                switch status {
                case .processing:
                    break
                case .waitingForUser:
                    continuation.yield(.success(.waitingForUser))
                case .finished(let result):
                    templateId = result.templateId
                    let sample = enrollmentSample(
                        templateId: result.templateId,
                        status: result.sampleStatus,
                        remaining: result.remainingSamples
                    )
                    continuation.yield(.success(sample))
                    if result.remainingSamples == 0 { return true }
                }
            }

            guard let templateId else { return false }

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
                        continuation.yield(.success(.waitingForUser))
                    case .finished(let result):
                        let sample = enrollmentSample(
                            templateId: templateId,
                            status: result.sampleStatus,
                            remaining: result.remainingSamples
                        )
                        continuation.yield(.success(sample))
                        if result.remainingSamples == 0 { return true }
                    }
                }
            }
            return false
        }

        private static func enrollmentSample(
            templateId: Data,
            status: SampleStatus,
            remaining: UInt
        ) -> EnrollmentSample {
            if remaining == 0 {
                return .completed(templateId: templateId, status: status)
            }
            return .sample(status: status, remaining: remaining)
        }
    }
}

// MARK: - EnrollmentSequence

extension CTAP2.BioEnrollment {

    /// An async sequence of enrolled fingerprint templates.
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

// MARK: - Private Wire Types

extension CTAP2.BioEnrollment {
    private enum Subcommand: UInt8, Sendable {
        case enrollBegin = 0x01
        case enrollCaptureNextSample = 0x02
        case cancelCurrentEnrollment = 0x03
        case enumerateEnrollments = 0x04
        case setFriendlyName = 0x05
        case removeEnrollment = 0x06
        case getFingerprintSensorInfo = 0x07
    }

    private enum SubcommandParam: UInt8, Sendable {
        case templateId = 0x01
        case templateFriendlyName = 0x02
        case timeoutMilliseconds = 0x03
    }

    private struct RequestParameters: Sendable, CBOR.Encodable {
        let subCommand: Subcommand
        let subCommandParams: [UInt8: CBOR.Value]?
        let pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion
        let pinUVAuthParam: Data

        func cbor() -> CBOR.Value {
            var map: [CBOR.Value: CBOR.Value] = [:]
            map[.int(0x01)] = .int(0x01)  // modality: fingerprint
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

    private struct RequestParametersNoAuth: Sendable, CBOR.Encodable {
        let subCommand: Subcommand

        func cbor() -> CBOR.Value {
            let map: [CBOR.Value: CBOR.Value] = [
                .int(0x01): .int(0x01),  // modality: fingerprint
                .int(0x02): .int(Int(subCommand.rawValue)),
            ]
            return .map(map)
        }
    }

}
