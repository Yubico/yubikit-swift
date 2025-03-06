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

struct SCPSessionKeys: CustomDebugStringConvertible {
    var debugDescription: String {
        "SCPSessionKeys(senc: \(senc.hexEncodedString), smac: \(smac.hexEncodedString), srmac: \(srmac.hexEncodedString), dek: \(String(describing: dek?.hexEncodedString)))"
    }
    
    let senc: Data
    let smac: Data
    let srmac: Data
    let dek: Data?
    
    init(senc: Data, smac: Data, srmac: Data, dek: Data?) {
        self.senc = senc
        self.smac = smac
        self.srmac = srmac
        self.dek = dek
    }
}
