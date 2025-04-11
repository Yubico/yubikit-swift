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


import CommonCrypto
import Security

public struct SCP11KeyParams: SCPKeyParams {
    public var keyRef: SCPKeyRef
    public let pkSdEcka: SecKey
    public let oceKeyRef: SCPKeyRef?
    public let skOceEcka: SecKey?
    public let certificates: [SecCertificate]
    
    // remove nullable fields in objc
    init(keyRef: SCPKeyRef, pkSdEcka: SecKey, oceKeyRef: SCPKeyRef? = nil, skOceEcka: SecKey? = nil, certificates: [SecCertificate] = []) {
        guard 0xff & keyRef.kid == 0x13 else {
            fatalError("Invalid KID for SCP03")
        }
        self.keyRef = keyRef
        self.pkSdEcka = pkSdEcka
        self.oceKeyRef = oceKeyRef
        self.skOceEcka = skOceEcka
        self.certificates = certificates
    }
}
