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

/// Features that may be supported by a SecurityDomain session.
///
/// This is an empty enum by design - SecurityDomain supports all operations
/// without version-specific features. The empty enum ensures that the
/// `supports` method cannot be called, reflecting that there are no
/// conditional features to check.
public enum SecurityDomainFeature: SessionFeature, Sendable {

    /// Checks if this feature is supported by the given firmware version.
    /// - Parameter version: The YubiKey firmware version.
    /// - Returns: `true` for all features (though this cannot be called due to the empty enum).
    public func isSupported(by version: Version) -> Bool {
        true
    }
}
