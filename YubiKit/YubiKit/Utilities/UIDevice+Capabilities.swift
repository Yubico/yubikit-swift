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

#if canImport(CoreNFC)
import CoreNFC
#endif

enum Device {
    /// Returns `true` when the current device has a Lightning (8-pin) port.
    /// List contains every Lightning-equipped model that can install iOS/iPadOS 16 or newer.
    static var hasLightningPort: Bool {
        var systemInfo = utsname()
        uname(&systemInfo)
        let model = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(validatingCString: $0) ?? ""
            }
        }

        switch model {
        // 8/8 Plus/X
        case "iPhone10,1", "iPhone10,2", "iPhone10,3", "iPhone10,4", "iPhone10,5", "iPhone10,6",
            // XS/XS Max/XR
            "iPhone11,2", "iPhone11,4", "iPhone11,6", "iPhone11,8",
            // 11 line + SE 2
            "iPhone12,1", "iPhone12,3", "iPhone12,5", "iPhone12,8",
            // 12 line
            "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4",
            // 13 line, SE 3, 14/14 Plus
            "iPhone14,2", "iPhone14,3", "iPhone14,4", "iPhone14,5", "iPhone14,6", "iPhone14,7", "iPhone14,8":
            return true

        // iPad 5
        case "iPad6,11", "iPad6,12",
            // iPad 6
            "iPad7,5", "iPad7,6",
            // iPad 7
            "iPad7,11", "iPad7,12",
            // iPad 8
            "iPad11,6", "iPad11,7",
            // iPad 9
            "iPad12,1", "iPad12,2",
            // iPad mini 5
            "iPad11,1", "iPad11,2",
            // iPad Air 3
            "iPad11,3", "iPad11,4":
            return true

        default:
            // everything else is USB-C
            return false
        }
    }

    #if canImport(CoreNFC)
    static var supportsNFC: Bool {
        NFCNDEFReaderSession.readingAvailable
    }
    #endif
}
