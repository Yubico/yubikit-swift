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

@Suite("USB smart card transport")
struct USBSmartCardTransportTests {
    @Test("YubiKey USB CCID ATR is not NFC")
    func usbATR() {
        let atr = Data([0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0])
        #expect(USBSmartCard.isNFC(atr: atr) == false)
    }

    @Test("NFC reader ATR is NFC")
    func nfcATR() {
        let atr = Data([0x3b, 0x8c, 0x80, 0x01, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69])
        #expect(USBSmartCard.isNFC(atr: atr))
    }

    @Test("missing or short ATR is NFC")
    func missingATR() {
        #expect(USBSmartCard.isNFC(atr: nil))
        #expect(USBSmartCard.isNFC(atr: Data([0x3b])))
    }

    @Test("ATR slices are indexed from their start")
    func slicedATR() {
        let atr = Data([0x00, 0x3b, 0xfd, 0x13]).dropFirst()
        #expect(USBSmartCard.isNFC(atr: atr) == false)
    }
}
