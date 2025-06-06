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

/// Management session features.
public enum ManagementFeature: SessionFeature {

    /// Support for reading the DeviceInfo data from the YubiKey.
    case deviceInfo
    /// Support for writing DeviceConfig data to the YubiKey.
    case deviceConfig
    /// Support for device-wide reset
    case deviceReset

    public func isSupported(by version: Version) -> Bool {
        switch self {
        case .deviceInfo:
            return version >= Version(withString: "4.1.0")!
        case .deviceConfig:
            return version >= Version(withString: "5.0.0")!
        case .deviceReset:
            return version >= Version(withString: "5.6.0")!
        }
    }
}
