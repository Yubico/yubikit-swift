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

/// Features that may be supported by an OATH session depending on the YubiKey firmware version.
public enum OATHSessionFeature: SessionFeature, Sendable {

    /// Ability to rename OATH credentials.
    case rename

    /// Touch requirement support for OATH operations.
    case touch

    /// SHA-512 algorithm support for OATH credentials.
    case sha512

    /// Checks if this feature is supported by the given firmware version.
    /// - Parameter version: The YubiKey firmware version.
    /// - Returns: `true` if the feature is supported, `false` otherwise.
    public func isSupported(by version: Version) -> Bool {
        switch self {
        case .rename:
            return version >= Version("5.3.0")!
        case .touch:
            return version >= Version("4.2.0")!
        case .sha512:
            return version >= Version("4.3.1")!
        }
    }
}
