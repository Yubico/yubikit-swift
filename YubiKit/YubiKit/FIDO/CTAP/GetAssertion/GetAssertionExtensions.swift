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

extension CTAP.GetAssertion {
    /// Extension inputs for the authenticatorGetAssertion command.
    ///
    /// > TODO: Extensions not yet implemented (hmac-secret, largeBlobKey, getCredBlob, appId, prf).
    ///
    /// - SeeAlso: [CTAP2.3 Extensions](https://fidoalliance.org/specs/fido-v2.3-rd-20251023/fido-client-to-authenticator-protocol-v2.3-rd-20251023.html#sctn-defined-extensions)
    struct Extensions: Sendable {
        init() {}
    }
}
