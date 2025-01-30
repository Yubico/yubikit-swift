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

import XCTest
@testable import YubiKit
import CommonCrypto

final class DataExtensionsTests: XCTestCase {
    
    func testShift() throws {
        let data = Data(hexEncodedString: "7df76b0c1ab899b33e42f047b91b546f")
        let shiftedDate = data?.shiftedLeftByOne()
        XCTAssertEqual(shiftedDate, Data(hexEncodedString: "fbeed618357133667c85e08f7236a8de"))
    }
    
    func testShiftLeftWithCarryOver() throws {
        let data = Data([0x01, 0xff, 0x03, 0x04])
        let shiftedData = data.shiftedLeftByOne()
        XCTAssertEqual(shiftedData, Data([0x03, 0xfe, 0x06, 0x08]))
        print(shiftedData.hexEncodedString)
    }
    
    func testShiftLeftWithCarryOverFirst() throws {
        let data = Data([0xff, 0x02, 0x03, 0x04])
        let shiftedData = data.shiftedLeftByOne()
        XCTAssertEqual(shiftedData, Data([0xfe, 0x04, 0x06, 0x08]))
        print(shiftedData.hexEncodedString)
    }
    
    func testShiftLeftWithCarryOverLast() throws {
        let data = Data([0x01, 0x02, 0x03, 0xff])
        let shiftedData = data.shiftedLeftByOne()
        XCTAssertEqual(shiftedData, Data([0x02, 0x04, 0x07, 0xfe]))
        print(shiftedData.hexEncodedString)
    }
    
    func testShiftLeftNoCarryOver() throws {
        let data = Data([0x01, 0x02, 0x03, 0x04])
        let shiftedData = data.shiftedLeftByOne()
        XCTAssertEqual(shiftedData, Data([0x02, 0x04, 0x06, 0x08]))
        print(shiftedData.hexEncodedString)
    }
    
    func testXor() throws {
        let data = Data([0x1F, 0x2B])
        let key = Data([0xAA, 0xBB])
        let result = data.xor(with: key)
        print(result.hexEncodedString)
        XCTAssertEqual(result, Data([0xb5, 0x90]))
    }
    
    func testXorLongerData() throws {
        let data = Data([0x1F, 0x2B, 0x3C])
        let key = Data([0xAA, 0xBB])
        let result = data.xor(with: key)
        print(result.hexEncodedString)
        XCTAssertEqual(result, Data([0xb5, 0x90]))
    }
    
    func testXorLongerKey() throws {
        let data = Data([0xAA, 0xBB])
        let key = Data([0x1F, 0x2B, 0x3C])
        let result = data.xor(with: key)
        print(result.hexEncodedString)
        XCTAssertEqual(result, Data([0xb5, 0x90]))
    }
}
