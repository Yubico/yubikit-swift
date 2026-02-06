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

// MARK: - AsyncSequence API

extension CTAP2.CredentialManagement {

    /// An async sequence of relying parties with stored credentials.
    ///
    /// Use this for lazy iteration over RPs, fetching each one on-demand:
    /// ```swift
    /// for try await rp in credMgmt.rps {
    ///     print(rp.rp.id)
    ///     if someCondition { break }  // Stops fetching early
    /// }
    /// ```
    ///
    /// To collect all RPs into an array, use ``RPSequence/enumerate()``.
    public var rps: RPSequence {
        RPSequence(credentialManagement: self)
    }

    /// An async sequence of credentials for a specific relying party.
    ///
    /// Use this for lazy iteration over credentials, fetching each one on-demand:
    /// ```swift
    /// for try await cred in credMgmt.credentials(for: rpIdHash) {
    ///     print(cred.user.name)
    /// }
    /// ```
    ///
    /// - Parameter rpIdHash: SHA-256 hash of the RP ID.
    /// - Returns: An async sequence of credentials for the specified RP.
    public func credentials(for rpIdHash: Data) -> CredentialSequence {
        CredentialSequence(credentialManagement: self, rpIdHash: rpIdHash)
    }
}

// MARK: - RP Sequence

extension CTAP2.CredentialManagement {

    /// An async sequence that lazily enumerates relying parties.
    public struct RPSequence: AsyncSequence, Sendable {
        public typealias Element = RPData

        fileprivate let credentialManagement: CTAP2.CredentialManagement

        /// Collects all relying parties into an array.
        public func enumerate() async throws(CTAP2.SessionError) -> [RPData] {
            var results = [RPData]()
            for try await rp in self {
                results.append(rp)
            }
            return results
        }

        public func makeAsyncIterator() -> Iterator {
            Iterator(credentialManagement: credentialManagement)
        }

        /// Iterator for lazily enumerating relying parties.
        public actor Iterator: AsyncIteratorProtocol {
            public typealias Element = RPData

            private let credentialManagement: CTAP2.CredentialManagement
            private var totalRPs: UInt = 0
            private var fetched: UInt = 0
            private var finished = false

            fileprivate init(credentialManagement: CTAP2.CredentialManagement) {
                self.credentialManagement = credentialManagement
            }

            public func next() async throws(CTAP2.SessionError) -> RPData? {
                guard !finished else { return nil }

                if fetched == 0 {
                    // First call - begin enumeration
                    guard let response = try await beginEnumeration() else {
                        finished = true
                        return nil
                    }
                    totalRPs = response.totalRPs ?? 0
                    guard totalRPs > 0 else {
                        finished = true
                        return nil
                    }
                    fetched = 1
                    finished = fetched >= totalRPs
                    return response.rpData
                }

                guard fetched < totalRPs else {
                    finished = true
                    return nil
                }

                // Subsequent calls - get next
                let response: EnumerateRPsResponse = try await credentialManagement.executeNoAuth(
                    subcommand: .enumerateRPsGetNextRP
                )
                fetched += 1
                finished = fetched >= totalRPs
                return response.rpData
            }

            private func beginEnumeration() async throws(CTAP2.SessionError) -> EnumerateRPsResponse? {
                do {
                    return try await credentialManagement.execute(subcommand: .enumerateRPsBegin)
                } catch .ctapError(.noCredentials, _) {
                    return nil
                }
            }
        }
    }
}

// MARK: - Credential Sequence

extension CTAP2.CredentialManagement {

    /// An async sequence that lazily enumerates credentials for a relying party.
    public struct CredentialSequence: AsyncSequence, Sendable {
        public typealias Element = CredentialData

        fileprivate let credentialManagement: CTAP2.CredentialManagement
        fileprivate let rpIdHash: Data

        /// Collects all credentials into an array.
        public func enumerate() async throws(CTAP2.SessionError) -> [CredentialData] {
            var results = [CredentialData]()
            for try await cred in self {
                results.append(cred)
            }
            return results
        }

        public func makeAsyncIterator() -> Iterator {
            Iterator(credentialManagement: credentialManagement, rpIdHash: rpIdHash)
        }

        /// Iterator for lazily enumerating credentials.
        public actor Iterator: AsyncIteratorProtocol {
            public typealias Element = CredentialData

            private let credentialManagement: CTAP2.CredentialManagement
            private let rpIdHash: Data
            private var totalCredentials: UInt = 0
            private var fetched: UInt = 0
            private var finished = false

            fileprivate init(credentialManagement: CTAP2.CredentialManagement, rpIdHash: Data) {
                self.credentialManagement = credentialManagement
                self.rpIdHash = rpIdHash
            }

            public func next() async throws(CTAP2.SessionError) -> CredentialData? {
                guard !finished else { return nil }

                if fetched == 0 {
                    // First call - begin enumeration
                    guard let response = try await beginEnumeration() else {
                        finished = true
                        return nil
                    }
                    totalCredentials = response.totalCredentials ?? 0
                    guard totalCredentials > 0 else {
                        finished = true
                        return nil
                    }
                    fetched = 1
                    finished = fetched >= totalCredentials
                    return response.credentialData
                }

                guard fetched < totalCredentials else {
                    finished = true
                    return nil
                }

                // Subsequent calls - get next
                let response: EnumerateCredentialsResponse = try await credentialManagement.executeNoAuth(
                    subcommand: .enumerateCredentialsGetNextCredential
                )
                fetched += 1
                finished = fetched >= totalCredentials
                return response.credentialData
            }

            private func beginEnumeration() async throws(CTAP2.SessionError) -> EnumerateCredentialsResponse? {
                let params: [UInt8: CBOR.Value] = [
                    Parameter.rpIdHash.rawValue: rpIdHash.cbor()
                ]
                do {
                    return try await credentialManagement.execute(
                        subcommand: .enumerateCredentialsBegin,
                        params: params
                    )
                } catch .ctapError(.noCredentials, _) {
                    return nil
                }
            }
        }
    }
}
