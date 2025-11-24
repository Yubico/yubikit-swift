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

extension PublicKeyCredential {
    /// Relying Party entity information.
    struct RPEntity: Sendable {
        /// Relying Party identifier (e.g., "example.com").
        let id: String

        /// Human-readable relying party name.
        let name: String?

        init(id: String, name: String? = nil) {
            self.id = id
            self.name = name
        }
    }
}
