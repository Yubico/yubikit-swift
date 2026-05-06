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

// MARK: - LargeBlob Extension

extension WebAuthn.Extension {

    /// The [largeBlob extension](https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
    /// for storing arbitrary data with credentials.
    ///
    /// This WebAuthn extension wraps the CTAP2 largeBlobKey extension and the
    /// LargeBlobs API, allowing relying parties to store and retrieve opaque
    /// data associated with credentials.
    ///
    /// ## Registration
    ///
    /// Request largeBlob support when creating a credential:
    ///
    /// ```swift
    /// let options = WebAuthn.Registration.Options(
    ///     ...,
    ///     extensions: .init(largeBlob: .required)
    /// )
    /// let response = try await client.makeCredential(options, authorization: .pin(pin)).value
    /// if response.clientExtensionResults.largeBlob?.supported == true {
    ///     // Credential supports large blob storage
    /// }
    /// ```
    ///
    /// ## Authentication (Read)
    ///
    /// Read a previously stored blob:
    ///
    /// ```swift
    /// let options = WebAuthn.Authentication.Options(
    ///     ...,
    ///     extensions: .init(largeBlob: .read)
    /// )
    /// let matches = try await client.getAssertion(options, authorization: .pin(pin)).value
    /// let response = matches[0]
    /// if let blob = response.clientExtensionResults.largeBlob?.blob {
    ///     // Use the retrieved blob data
    /// }
    /// ```
    ///
    /// ## Authentication (Write)
    ///
    /// Store a blob with a credential:
    ///
    /// ```swift
    /// let options = WebAuthn.Authentication.Options(
    ///     ...,
    ///     allowCredentials: [.init(id: credentialId)],
    ///     extensions: .init(largeBlob: .write(myData))
    /// )
    /// let matches = try await client.getAssertion(options, authorization: .pin(pin)).value
    /// let response = matches[0]
    /// if response.clientExtensionResults.largeBlob?.written == true {
    ///     // Blob stored successfully
    /// }
    /// ```
    public enum LargeBlob {}
}

// MARK: - Support Level

extension WebAuthn.Extension.LargeBlob {

    /// Whether large blob support is required or preferred.
    public enum Support: String, Sendable, Equatable {
        /// Registration fails if the authenticator doesn't support large blobs.
        case required
        /// Large blob support is preferred but not required.
        case preferred
    }
}

// MARK: - Registration Input/Output

extension WebAuthn.Extension.LargeBlob {

    /// Namespace for largeBlob registration types.
    public enum Registration {
        /// Input for largeBlob extension at registration.
        public struct Input: Sendable, Equatable {
            /// Whether large blob support is required or preferred.
            public let support: Support

            public init(support: Support) {
                self.support = support
            }

            /// Require large blob support (registration fails if unsupported).
            public static let required = Self(support: .required)

            /// Prefer large blob support (registration succeeds either way).
            public static let preferred = Self(support: .preferred)
        }

        /// Output from largeBlob extension at registration.
        public struct Output: Sendable, Equatable {
            /// Whether the created credential supports large blob storage.
            public let supported: Bool

            public init(supported: Bool) {
                self.supported = supported
            }
        }
    }
}

// MARK: - Authentication Input/Output

extension WebAuthn.Extension.LargeBlob {

    /// Namespace for largeBlob authentication types.
    public enum Authentication {
        /// Input for largeBlob extension at authentication.
        ///
        /// Read and write are mutually exclusive, enforced by the enum.
        public enum Input: Sendable, Equatable {
            /// Read the blob associated with the asserted credential.
            case read
            /// Write a blob to the asserted credential's large blob storage.
            case write(Data)
        }

        /// Output from largeBlob extension at authentication.
        public struct Output: Sendable, Equatable {
            /// The retrieved blob data (present when `read` was requested).
            ///
            /// `nil` if no blob was stored or the read failed.
            public let blob: Data?

            /// Whether the write succeeded (present when `write` was requested).
            public let written: Bool?

            public init(blob: Data? = nil, written: Bool? = nil) {
                self.blob = blob
                self.written = written
            }
        }
    }
}
