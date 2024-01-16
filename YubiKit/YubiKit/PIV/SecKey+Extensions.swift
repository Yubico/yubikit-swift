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

extension SecKey {
    
    var type: PIVKeyType? {
        guard let attributes = SecKeyCopyAttributes(self) as? Dictionary<String, Any>,
              let size = attributes[kSecAttrKeySizeInBits as String] as? UInt,
              let type = attributes[kSecAttrKeyType as String] as? String else { return nil }
        if type == kSecAttrKeyTypeRSA as String {
            if size == 1024 {
                return .RSA1024
            }
            if size == 2048 {
                return .RSA2048
            }
        }
        if type == kSecAttrKeyTypeEC as String {
            if size == 256 {
                return .ECCP256
            }
            if size == 384 {
                return .ECCP384
            }
        }
        return nil
    }
    
}
