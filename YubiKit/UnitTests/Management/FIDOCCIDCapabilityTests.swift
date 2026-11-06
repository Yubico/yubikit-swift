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
import Testing

@testable import YubiKit

struct FIDOCCIDCapabilityTests {
    @Test("Decode and configure the Android FIDO-over-CCID capability mask")
    func configuration() {
        // Android 3.3.0 DeviceInfoTest.testGetName: the final fixture reports 0x1206.
        let info = DeviceInfo(
            withTlvs: [0x01: Data([0x12, 0x06]), 0x03: Data([0x12, 0x06])],
            fallbackVersion: Version("5.8.0")!
        )
        #expect(info.isApplicationSupported(.fidoCCID, over: .usb))
        #expect(info.config.isApplicationEnabled(.fidoCCID, over: .usb))
        let disabled = info.config.disable(application: .fidoCCID, over: .usb)
        #expect(disabled.enabledCapabilities[.usb] == 0x0206)
    }
}
