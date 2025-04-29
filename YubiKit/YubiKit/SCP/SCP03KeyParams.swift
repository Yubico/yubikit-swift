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

public struct SCP03KeyParams: SCPKeyParams {
    public var keyRef: SCPKeyRef
    public var staticKeys: StaticKeys
    
    init(keyRef: SCPKeyRef, staticKeys: StaticKeys) {
        if 0xFF & keyRef.kid > 3 {
            fatalError("Invalid KID for SCP03")
        }
        self.keyRef = keyRef
        self.staticKeys = staticKeys
    }
}
