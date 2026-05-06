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

extension WebAuthn {

    /// A validated WebAuthn origin.
    ///
    /// Extracts `scheme://host[:port]` from any URL. Path, query, and fragment are stripped.
    /// Enforces the [W3C secure-context rule](https://w3c.github.io/webappsec-secure-contexts/):
    /// only `https://` is accepted, with an exception for `http://localhost` (and
    /// `*.localhost`) for local development. The origin concept itself is defined by
    /// [RFC 6454](https://tools.ietf.org/html/rfc6454).
    ///
    /// ```swift
    /// let origin = try WebAuthn.Origin("https://example.com/login?foo=bar")
    /// // origin.stringValue == "https://example.com"
    ///
    /// let withPort = try WebAuthn.Origin("https://example.com:8443/api")
    /// // withPort.stringValue == "https://example.com:8443"
    ///
    /// let localhost = try WebAuthn.Origin("http://localhost:3000")  // allowed for development
    ///
    /// let insecure = try WebAuthn.Origin("http://example.com")  // throws .insecureContext
    /// ```
    public struct Origin: Sendable, Hashable, CustomStringConvertible {

        /// Errors that can occur when creating an Origin.
        public enum Error: Swift.Error, Sendable {
            /// The string is not a valid URL.
            case invalidURL(String)
            /// The URL is missing a scheme.
            case missingScheme
            /// The URL is missing a host.
            case missingHost
            /// The URL is not a secure context (must be `https` or `http://localhost`,
            /// including `*.localhost`).
            case insecureContext(String)
        }

        /// The serialized origin (`scheme://host[:port]`).
        public let stringValue: String

        /// The host component.
        public let host: String

        public var description: String { stringValue }

        /// Creates an origin from a string.
        ///
        /// - Parameter string: A URL string.
        /// - Throws: ``Error`` if the string is not a valid secure origin.
        public init(_ string: String) throws(Error) {
            guard let url = URL(string: string) else {
                throw Error.invalidURL(string)
            }
            try self.init(url)
        }

        /// Creates an origin by extracting `scheme://host[:port]` from a URL.
        ///
        /// Path, query, and fragment are stripped.
        ///
        /// - Parameter url: A URL.
        /// - Throws: ``Error`` if the URL is not a secure context.
        public init(_ url: URL) throws(Error) {
            guard let scheme = url.scheme?.lowercased() else {
                throw Error.missingScheme
            }
            guard let host = url.host, !host.isEmpty else {
                throw Error.missingHost
            }

            // Secure context: https, or http only for localhost
            guard scheme == "https" || (scheme == "http" && Self.isLoopback(host)) else {
                throw Error.insecureContext("\(scheme)://\(host)")
            }

            self.host = host
            if let port = url.port {
                self.stringValue = "\(scheme)://\(host):\(port)"
            } else {
                self.stringValue = "\(scheme)://\(host)"
            }
        }

        /// Checks if a host is localhost per W3C Secure Contexts spec.
        ///
        /// Only accepts `localhost` and `*.localhost`. Raw IPs (127.0.0.1, ::1) are
        /// spec-allowed but omitted here for simplicity.
        private static func isLoopback(_ host: String) -> Bool {
            let lowercased = host.lowercased()
            return lowercased == "localhost" || lowercased.hasSuffix(".localhost")
        }
    }
}
