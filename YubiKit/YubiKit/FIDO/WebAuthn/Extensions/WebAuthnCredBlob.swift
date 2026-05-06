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

// MARK: - CredBlob Extension

extension WebAuthn.Extension {

    /// The [credBlob extension](https://www.w3.org/TR/webauthn-3/#sctn-credBlob-extension)
    /// for storing small data blobs with credentials.
    ///
    /// This WebAuthn extension wraps the CTAP2 credBlob extension, allowing
    /// relying parties to store and retrieve small amounts of data with
    /// discoverable credentials.
    ///
    /// ## Registration
    ///
    /// Store a blob when creating a credential:
    ///
    /// ```swift
    /// let options = WebAuthn.Registration.Options(
    ///     ...,
    ///     residentKey: .required,
    ///     extensions: .init(credBlob: myBlobData)
    /// )
    /// let response = try await client.makeCredential(options, authorization: .pin(pin)).value
    /// if response.clientExtensionResults.credBlob?.stored == true {
    ///     // Blob was stored successfully
    /// }
    /// ```
    ///
    /// ## Authentication
    ///
    /// Retrieve the stored blob:
    ///
    /// ```swift
    /// let options = WebAuthn.Authentication.Options(
    ///     ...,
    ///     extensions: .init(getCredBlob: true)
    /// )
    /// let matches = try await client.getAssertion(options, authorization: .pin(pin)).value
    /// let response = matches[0]
    /// if let blob = response.clientExtensionResults.credBlob?.blob {
    ///     // Use the retrieved blob data
    /// }
    /// ```
    ///
    /// - Note: credBlob requires discoverable credentials (`residentKey: .required`).
    public enum CredBlob {}
}

// MARK: - Registration Input/Output

extension WebAuthn.Extension.CredBlob {

    /// Namespace for credBlob registration types.
    public enum Registration {

        /// Input for credBlob extension at registration.
        ///
        /// The blob data to store with the credential. Must not exceed
        /// `maxCredBlobLength` reported by the authenticator.
        public typealias Input = Data

        /// Output from credBlob extension at registration.
        public struct Output: Sendable, Equatable {
            /// Whether the blob was stored successfully.
            public let stored: Bool

            public init(stored: Bool) {
                self.stored = stored
            }
        }
    }
}

// MARK: - Authentication Input/Output

extension WebAuthn.Extension.CredBlob {

    /// Namespace for credBlob authentication types.
    public enum Authentication {

        /// Input for credBlob extension at authentication.
        ///
        /// Set to `true` to request retrieval of the stored blob.
        public typealias Input = Bool

        /// Output from credBlob extension at authentication.
        public struct Output: Sendable, Equatable {
            /// The blob data stored during registration.
            public let blob: Data

            public init(blob: Data) {
                self.blob = blob
            }
        }
    }
}
