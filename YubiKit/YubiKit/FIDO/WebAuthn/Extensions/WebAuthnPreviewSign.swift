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

// MARK: - PreviewSign Extension

extension WebAuthn.Extension {

    /// The previewSign extension for delegated signing.
    ///
    /// Implements version 4 of the sign CTAP2 extension.
    ///
    /// https://github.com/yubicolabs/webauthn-sign-extension
    ///
    /// - Warning: This extension is currently in draft status and should be
    ///   considered experimental. It is not part of the stable API of this library.
    public enum PreviewSign {}
}

// MARK: - Signing Parameters

extension WebAuthn.Extension.PreviewSign {

    /// Parameters for signing with a specific credential's generated key.
    public struct SigningParams: Sendable, Equatable {
        /// The key handle from the generated key.
        public let keyHandle: Data

        /// The data to be signed (typically a hash).
        public let tbs: Data

        /// Optional CBOR-encoded additional arguments (e.g., ARKG derivation parameters).
        public let additionalArgs: Data?

        public init(keyHandle: Data, tbs: Data, additionalArgs: Data? = nil) {
            self.keyHandle = keyHandle
            self.tbs = tbs
            self.additionalArgs = additionalArgs
        }
    }
}

// MARK: - Registration Input/Output

extension WebAuthn.Extension.PreviewSign {

    /// Namespace for previewSign registration types.
    public enum Registration {

        /// Input for previewSign extension at registration.
        public struct Input: Sendable, Equatable {
            /// The COSE algorithm identifiers the RP supports for key generation.
            public let algorithms: [COSE.Algorithm]

            public init(algorithms: [COSE.Algorithm]) {
                self.algorithms = algorithms
            }

            /// Creates a generateKey input with the specified algorithms.
            public static func generateKey(algorithms: [COSE.Algorithm]) -> Input {
                Input(algorithms: algorithms)
            }
        }

        /// Output from previewSign extension at registration.
        public struct Output: Sendable, Equatable {
            /// The generated key pair information.
            public let generatedKey: CTAP2.Extension.PreviewSign.GeneratedKey

            public init(generatedKey: CTAP2.Extension.PreviewSign.GeneratedKey) {
                self.generatedKey = generatedKey
            }
        }
    }
}

// MARK: - Authentication Input/Output

extension WebAuthn.Extension.PreviewSign {

    /// Namespace for previewSign authentication types.
    public enum Authentication {

        /// Input for previewSign extension at authentication.
        public struct Input: Sendable, Equatable {
            /// Mapping from credential ID to signing parameters.
            public let signByCredential: [Data: SigningParams]

            public init(signByCredential: [Data: SigningParams]) {
                self.signByCredential = signByCredential
            }
        }

        /// Output from previewSign extension at authentication.
        public struct Output: Sendable, Equatable {
            /// The signature produced by the authenticator.
            public let signature: Data

            public init(signature: Data) {
                self.signature = signature
            }
        }
    }
}
