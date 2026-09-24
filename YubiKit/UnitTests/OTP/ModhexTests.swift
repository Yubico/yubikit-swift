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

struct ModhexTests {

    @Test("encodes the reference vectors")
    func encodes() {
        #expect(YubiOTP.Modhex.encode(Data()) == "")
        #expect(YubiOTP.Modhex.encode(Data([0x00])) == "cc")
        #expect(YubiOTP.Modhex.encode(Data([0xFF])) == "vv")
        #expect(YubiOTP.Modhex.encode(Data([0x2D, 0x34, 0x4E, 0x83])) == "dteffuje")
        #expect(
            YubiOTP.Modhex.encode(Data([0x69, 0xB6, 0x48, 0x1C, 0x8B, 0xAB, 0xA2, 0xB6, 0x0E, 0x8F]))
                == "hknhfjbrjnlnldnhcujv"
        )
    }

    @Test("decodes the reference vectors")
    func decodes() {
        #expect(YubiOTP.Modhex.decode("") == Data())
        #expect(YubiOTP.Modhex.decode("dteffuje") == Data([0x2D, 0x34, 0x4E, 0x83]))
        #expect(
            YubiOTP.Modhex.decode("hknhfjbrjnlnldnhcujv")
                == Data([0x69, 0xB6, 0x48, 0x1C, 0x8B, 0xAB, 0xA2, 0xB6, 0x0E, 0x8F])
        )
    }

    @Test("decoding is case-insensitive")
    func decodesUppercase() {
        #expect(YubiOTP.Modhex.decode("DTEFFUJE") == Data([0x2D, 0x34, 0x4E, 0x83]))
    }

    @Test("malformed input is rejected")
    func rejectsMalformed() {
        #expect(YubiOTP.Modhex.decode("abc") == nil, "odd length")
        #expect(YubiOTP.Modhex.decode("ca") == nil, "'a' is not in the modhex alphabet")
        #expect(YubiOTP.Modhex.decode("c!") == nil, "punctuation is not in the modhex alphabet")
    }
}
