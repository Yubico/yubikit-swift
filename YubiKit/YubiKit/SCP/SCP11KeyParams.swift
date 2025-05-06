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
    public let keyRef: SCPKeyRef
    public let pkSdEcka: SecKey
    public let oceKeyRef: SCPKeyRef?
    public let skOceEcka: SecKey?
    public let certificates: [SecCertificate]
    
    public init(keyRef: SCPKeyRef, pkSdEcka: SecKey, oceKeyRef: SCPKeyRef? = nil, skOceEcka: SecKey? = nil, certificates: [SecCertificate] = []) throws(SCPError) {
        switch (keyRef.kid) {
        case .scp11b:
            if (oceKeyRef != nil || skOceEcka != nil || !certificates.isEmpty) {
                throw .illegalArgument("Cannot provide oceKeyRef, skOceEcka or certificates for SCP11b")
            }
        case .scp11a:
            fallthrough
        case .scp11c:
            if (oceKeyRef == nil || skOceEcka == nil || certificates.isEmpty) {
                throw .illegalArgument("Must provide oceKeyRef, skOceEcka or certificates for SCP11a/c")
            }
        default:
            throw .illegalArgument("KID must be 0x11, 0x13, or 0x15 for SCP11")
        }
        self.keyRef = keyRef
        self.pkSdEcka = pkSdEcka
        self.oceKeyRef = oceKeyRef
        self.skOceEcka = skOceEcka
        self.certificates = certificates
    }
}
