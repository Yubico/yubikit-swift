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
import Foundation
import Testing

@testable import YubiKit

struct DataExtensionsTests {

    @Test func shiftLeftWithCarryOver() throws {
        let data = Data([0x01, 0xff, 0x03, 0x04])
        let shiftedData = data.shiftedLeftByOne()
        //print(shiftedData.hexEncodedString)
        #expect(shiftedData == Data([0x03, 0xfe, 0x06, 0x08]))
    }

    @Test func shiftLeftWithCarryOverFirst() throws {
        let data = Data([0xff, 0x02, 0x03, 0x04])
        let shiftedData = data.shiftedLeftByOne()
        //print(shiftedData.hexEncodedString)
        #expect(shiftedData == Data([0xfe, 0x04, 0x06, 0x08]))
    }

    @Test func shiftLeftWithCarryOverLast() throws {
        let data = Data([0x01, 0x02, 0x03, 0xff])
        let shiftedData = data.shiftedLeftByOne()
        //print(shiftedData.hexEncodedString)
        #expect(shiftedData == Data([0x02, 0x04, 0x07, 0xfe]))
    }

    @Test func shiftLeftNoCarryOver() throws {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        let shiftedData = data.shiftedLeftByOne()
        //print(shiftedData.hexEncodedString)
        #expect(shiftedData == Data([0x02, 0x04, 0x06, 0x08]))
    }

    @Test func xor() throws {
        let data = Data([0x1F, 0x2B])
        let key = Data([0xAA, 0xBB])
        let result = data.xor(with: key)
        //print(result.hexEncodedString)
        #expect(result == Data([0xb5, 0x90]))
    }

    // MARK: - Bounds-safe integer accessors

    @Test func uint16IsNilWhenFewerThanTwoBytes() throws {
        #expect(Data().uint16 == nil)
        #expect(Data([0x01]).uint16 == nil)
    }

    @Test func uint16ReadsLeadingTwoBytes() throws {
        // Host order is little-endian on all Apple platforms; callers apply .bigEndian.
        #expect(Data([0x34, 0x12]).uint16 == 0x1234)
        // Trailing bytes beyond the first two are ignored, not rejected.
        #expect(Data([0x34, 0x12, 0xff, 0xff]).uint16 == 0x1234)
    }

    @Test func uint32IsNilWhenFewerThanFourBytes() throws {
        #expect(Data().uint32 == nil)
        #expect(Data([0x01]).uint32 == nil)
        #expect(Data([0x01, 0x02]).uint32 == nil)
        #expect(Data([0x01, 0x02, 0x03]).uint32 == nil)
    }

    @Test func uint32ReadsLeadingFourBytes() throws {
        #expect(Data([0x78, 0x56, 0x34, 0x12]).uint32 == 0x1234_5678)
        // Trailing bytes beyond the first four are ignored, not rejected.
        #expect(Data([0x78, 0x56, 0x34, 0x12, 0xff]).uint32 == 0x1234_5678)
    }
}
