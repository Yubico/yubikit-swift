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

public enum PIVSessionFeature: SessionFeature {
    
    case usagePolicy, aesKey, serialNumber, metadata, attestation, p384, touchCached, rsaGeneration, rsa3072and4096
     
    public func isSupported(by version: Version) -> Bool {
        switch self {
        case .usagePolicy:
            return version >= Version(withString: "4.0.0")!
        case .aesKey:
            return version >= Version(withString: "5.4.0")!
        case .serialNumber:
            return version >= Version(withString: "5.0.0")!
        case .metadata:
            return version >= Version(withString: "5.3.0")!
        case .attestation:
            return version >= Version(withString: "4.3.0")!
        case .p384:
            return version >= Version(withString: "4.0.0")!
        case .touchCached:
            return version >= Version(withString: "4.3.0")!
        case .rsaGeneration:
            return version < Version(withString: "4.2.6")! || version >= Version(withString: "4.3.5")!
        case .rsa3072and4096:
            return version >= Version(withString: "5.7.0")!
        }
    }
}
