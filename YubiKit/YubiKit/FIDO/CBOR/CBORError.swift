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

extension CBOR {
    /// Errors that can occur during CBOR decoding.
    ///
    /// These errors indicate malformed or unsupported CBOR data received from the authenticator.
    public enum Error: Swift.Error, Equatable {
        /// The CBOR data ended unexpectedly while parsing.
        case unexpectedEndOfData

        /// Extra bytes remain after parsing a complete CBOR value.
        case extraneousData

        /// A text string contains invalid UTF-8 data.
        case invalidUTF8

        /// The CBOR major type is not supported (e.g., tagged values, floats).
        case unsupportedMajorType(UInt8)

        /// The CBOR simple value is not supported (only true, false, null are supported).
        case unsupportedSimpleValue(UInt8)

        /// The additional info byte has an invalid value for integer encoding.
        case invalidAdditionalInfo(UInt8)
    }
}

protocol CBORError {
    static func cborError(
        _ error: CBOR.Error,
        source: SourceLocation
    ) -> Self
}
