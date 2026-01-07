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

extension Data {

    /// Compares two Data values in constant time to prevent timing attacks.
    internal func constantTimeCompare(_ other: Data) -> Bool {
        guard self.count == other.count else { return false }
        return zip(self, other).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }
}
