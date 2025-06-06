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

extension Array {
    func tuples() -> [(Element, Element)]? {
        if self.count % 2 == 0 {
            return stride(from: 0, to: count, by: 2).map {
                (self[$0], self[$0.advanced(by: 1)])
            }
        } else {
            return nil
        }
    }
}
