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

// MARK: - RP ID Validation

extension WebAuthn.Client {

    /// Validates that the RP ID is allowed for the given origin.
    ///
    /// Per WebAuthn spec, the RP ID must be equal to or a registrable suffix of the origin's host,
    /// and must not be a public suffix (e.g., "co.uk", "github.io").
    func validateRpId(_ rpId: String, origin: WebAuthn.Origin) -> WebAuthn.ClientError? {
        let rpIdLower = rpId.lowercased()
        let hostLower = origin.host.lowercased()

        // RP ID cannot be a public suffix (e.g., "co.uk", "github.io")
        if isPublicSuffix(rpIdLower) {
            return .invalidRequest(
                "RP ID '\(rpId)' is a public suffix",
                source: .here()
            )
        }

        // RP ID must be equal to or a registrable suffix of the origin's host
        guard hostLower == rpIdLower || hostLower.hasSuffix("." + rpIdLower) else {
            return .invalidRequest(
                "RP ID '\(rpId)' is not valid for origin '\(origin)'",
                source: .here()
            )
        }
        return nil
    }
}
