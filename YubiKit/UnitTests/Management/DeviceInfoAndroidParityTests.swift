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

import CryptoTokenKit
import Foundation
import Testing

@testable import YubiKit

struct DeviceInfoAndroidParityTests {
    // Exact TLV payloads and expected names from DeviceInfoTest.testGetName at Android 76b89d35.
    private static let fixtures: [(String, String)] = [
        (
            "YubiKey 5C NFC - Enhanced PIN",
            "0102033f0302033f0204020b885b04010305030507040602000007010f0801000d02033f0e02033f0a01000f01"
                + "0020030000002103000000100101110400000000120100130c3738434c55465835303030501402000015"
                + "02000016010117010018020000"
        ),
        (
            "YubiKey 5C NFC FIPS",
            "0102033d0302033d020401ea505104018305030507040602000007010f0801000d02033d0e02033d0a01000f01"
                + "0020030000002103000000100101110400000000120100130c3738434c55465835303030501402001f15"
                + "02001f16010117010018020000"
        ),
        (
            "YubiKey 5 Nano",
            "0102033f0302033e020401c234c404010205030507010602000007010f0801000a01000f010020030000002103"
                + "000000100101110400000000120100130c3738434c554658353030305014020000150200081601001701"
                + "00"
        ),
        (
            "YubiKey Bio - FIDO Edition",
            "0102020203020202020401afba5c04010605030507020602000007010f0801000a01000f010020030005012103"
                + "030001100101110400000000120100130c3738434c554658353030305014020000150200001601001701"
                + "0018020000"
        ),
        (
            "YubiKey C Bio - Multi-protocol Edition",
            "0102061203020612020401afcfff04010705030507020602000007010f0801000a01000f010020030005012103"
                + "030001100101110400000000120100130c3738434c554658353030305014020000150200001601001701"
                + "0018020200"
        ),
        (
            "Security Key C NFC - Enterprise Edition",
            "01020202030202020204017b306c04014305030504030602000007010f0801000d0202060e0202060a01000f01"
                + "00"
        ),
        (
            "YubiKey 5Ci",
            "0102023f0302023f020400a0392204010505030502030602000007010f0801000a01000f010c"
        ),
        (
            "YubiKey C Bio - FIDO Edition",
            "01021206030212060204023251e904010705030000010602000007010f0801000a01000f010020030100002103"
                + "030001100101110400000000120100130c3738434c554658353030305014020000150200001601001701"
                + "0018020000190e0103050800020101030400000003"
        ),
    ]

    @Test("Android naming fixtures", arguments: fixtures)
    func names(expected: String, encoded: String) throws {
        let data = try #require(Data(hexEncodedString: encoded))
        let tlvs = try #require(TKBERTLVRecord.dictionaryOfData(from: data))
        let info = DeviceInfo(withTlvs: tlvs, fallbackVersion: Version("5.7.0")!)
        #expect(info.deviceName == expected)
    }
}
