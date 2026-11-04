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

    // DeviceInfoTest.testParseVersionQualifier (Android), plus Rust's alpha-3 fixture.
    @Test(
        "Firmware qualifier fixtures",
        arguments: [
            (nil, nil, "2.2.2", DeviceInfo.VersionQualifier.ReleaseType.final, UInt32(0)),
            ("030403", nil, "3.4.3", .final, 0),
            ("000001", "0103050403020100030400000000", "5.4.3", .alpha, 0),
            ("000001", "01030507080201010304000000e9", "5.7.8", .beta, 233),
            ("050404", "0103050404020102030400000005", "5.4.4", .final, 5),
            ("050709", "01030507090201020304ffffffff", "5.7.9", .final, UInt32.max),
            ("050701", "0103050800020100030103", "5.8.0", .alpha, 3),
        ] as [(String?, String?, String, DeviceInfo.VersionQualifier.ReleaseType, UInt32)]
    )
    func qualifiers(
        firmware: String?,
        encoded: String?,
        expected: String,
        releaseType: DeviceInfo.VersionQualifier.ReleaseType,
        iteration: UInt32
    ) {
        var tlvs: [TKTLVTag: Data] = [:]
        tlvs[0x05] = firmware.flatMap { Data(hexEncodedString: $0) }
        tlvs[0x19] = encoded.flatMap { Data(hexEncodedString: $0) }
        let info = DeviceInfo(withTlvs: tlvs, fallbackVersion: Version("2.2.2")!)
        #expect(info.version == Version(expected)!)
        #expect(info.versionQualifier.version == Version(expected)!)
        #expect(info.versionQualifier.releaseType == releaseType)
        #expect(info.versionQualifier.iteration == iteration)
    }

    @Test("Unknown release types preserve the reported firmware version")
    func unknownReleaseType() {
        let info = DeviceInfo(
            withTlvs: [
                0x05: Data([5, 7, 1]),
                0x19: Data([1, 3, 5, 8, 0, 2, 1, 3, 3, 1, 3]),
            ],
            fallbackVersion: Version("0.0.1")!
        )
        #expect(info.version == Version("5.7.1")!)
        #expect(info.versionQualifier.version == Version("5.8.0")!)
        #expect(info.versionQualifier.releaseType == .final)
    }

}
