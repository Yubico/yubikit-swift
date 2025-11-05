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

/// Unit tests for CBOR functionality, ported from the Java SDK CborTest.java
@Suite("CBOR Encoding and Decoding Tests")
struct CBORTests {

    // MARK: - Integer Tests

    @Test(
        "Encode and decode integers",
        arguments: [
            ("00", CBOR.Value(0)),
            ("01", CBOR.Value(1)),
            ("0a", CBOR.Value(10)),
            ("17", CBOR.Value(23)),
            ("1818", CBOR.Value(24)),
            ("1819", CBOR.Value(25)),
            ("1864", CBOR.Value(100)),
            ("1903e8", CBOR.Value(1000)),
            ("1a000f4240", CBOR.Value(1_000_000)),
            ("19ffff", CBOR.Value(65535)),
            ("1a00010000", CBOR.Value(65536)),
            ("1a7fffffff", CBOR.Value(Int32.max)),
            ("20", CBOR.Value(-1)),
            ("29", CBOR.Value(-10)),
            ("37", CBOR.Value(-24)),
            ("3818", CBOR.Value(-25)),
            ("3863", CBOR.Value(-100)),
            ("3903e7", CBOR.Value(-1000)),
            ("3a7fffffff", CBOR.Value(Int32.min)),
        ]
    )
    func testIntegers(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncodeAndDecode(expectedHex: expectedHex, value: value)
    }

    // MARK: - Boolean Tests

    @Test(
        "Encode and decode booleans",
        arguments: [
            ("f4", CBOR.Value(false)),
            ("f5", CBOR.Value(true)),
        ]
    )
    func testBooleans(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncodeAndDecode(expectedHex: expectedHex, value: value)
    }

    // MARK: - Byte Array Tests

    @Test(
        "Encode and decode byte arrays",
        arguments: [
            ("40", CBOR.Value(Data())),
            ("4401020304", CBOR.Value(Data([1, 2, 3, 4]))),
        ]
    )
    func testByteArrays(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncodeAndDecode(expectedHex: expectedHex, value: value)
    }

    // MARK: - String Tests

    @Test(
        "Encode and decode strings",
        arguments: [
            ("60", CBOR.Value("")),
            ("6161", CBOR.Value("a")),
            ("6449455446", CBOR.Value("IETF")),
            ("62225c", CBOR.Value("\"\\")),
            ("62c3bc", CBOR.Value("ü")),
            ("63e6b0b4", CBOR.Value("水")),
            ("64f0909191", CBOR.Value("\u{10451}")),  // Unicode scalar U+10451
        ]
    )
    func testStrings(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncodeAndDecode(expectedHex: expectedHex, value: value)
    }

    // MARK: - Array Tests

    @Test("Encode and decode empty array") func testEmptyArray() throws {
        let value = CBOR.Value([])
        try assertCBOREncodeAndDecode(expectedHex: "80", value: value)
    }

    @Test("Encode and decode simple array") func testSimpleArray() throws {
        let value: CBOR.Value = [1, 2, 3]
        try assertCBOREncodeAndDecode(expectedHex: "83010203", value: value)
    }

    @Test("Encode and decode nested array") func testNestedArray() throws {
        let value: CBOR.Value = [1, [2, 3], [4, 5]]
        try assertCBOREncodeAndDecode(expectedHex: "8301820203820405", value: value)
    }

    @Test("Encode and decode array with 25 elements") func testLargeArray() throws {
        let items = (1...25).map { CBOR.Value($0) }
        let value = CBOR.Value(items)
        try assertCBOREncodeAndDecode(
            expectedHex: "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            value: value
        )
    }

    // MARK: - Map Tests

    @Test("Encode and decode empty map") func testEmptyMap() throws {
        let value = CBOR.Value([:] as [CBOR.Value: CBOR.Value])
        try assertCBOREncodeAndDecode(expectedHex: "a0", value: value)
    }

    @Test("Encode and decode simple map") func testSimpleMap() throws {
        let value: CBOR.Value = [1: 2, 3: 4]
        try assertCBOREncodeAndDecode(expectedHex: "a201020304", value: value)
    }

    @Test("Encode and decode map with string keys") func testMapWithStringKeys() throws {
        let value: CBOR.Value = ["a": 1, "b": [2, 3]]
        try assertCBOREncodeAndDecode(expectedHex: "a26161016162820203", value: value)
    }

    @Test("Encode and decode array containing map") func testArrayContainingMap() throws {
        let value: CBOR.Value = ["a", ["b": "c"]]
        try assertCBOREncodeAndDecode(expectedHex: "826161a161626163", value: value)
    }

    @Test("Encode map with multiple string keys (canonical ordering)") func testMapKeyOrdering() throws {
        // Map should be encoded in canonical order: a, b, c, d, e
        let value: CBOR.Value = ["c": "C", "d": "D", "a": "A", "b": "B", "e": "E"]
        try assertCBOREncodeAndDecode(
            expectedHex: "a56161614161626142616361436164614461656145",
            value: value
        )
    }

    // MARK: - Key Ordering Tests

    @Test("Canonical key ordering - mixed types") func testKeyOrderMixedTypes() throws {
        let value = CBOR.Value([
            CBOR.Value("3"): CBOR.Value(0),
            CBOR.Value(Data("2".utf8)): CBOR.Value(0),
            CBOR.Value(1): CBOR.Value(0),
        ])
        try assertCBOREncode(expectedHex: "a30100413200613300", value: value)
    }

    @Test("Canonical key ordering - with empty byte string") func testKeyOrderEmptyByteString() throws {
        let value = CBOR.Value([
            CBOR.Value("3"): CBOR.Value(0),
            CBOR.Value(Data()): CBOR.Value(0),
            CBOR.Value(256): CBOR.Value(0),
        ])
        try assertCBOREncode(expectedHex: "a3190100004000613300", value: value)
    }

    @Test("Canonical key ordering - integer keys") func testKeyOrderIntegers() throws {
        let value = CBOR.Value([
            CBOR.Value(Int32.max): CBOR.Value(0),
            CBOR.Value(255): CBOR.Value(0),
            CBOR.Value(256): CBOR.Value(0),
            CBOR.Value(0): CBOR.Value(0),
        ])
        try assertCBOREncode(expectedHex: "a4000018ff00190100001a7fffffff00", value: value)
    }

    @Test("Canonical key ordering - byte string keys different lengths") func testKeyOrderByteStrings() throws {
        let value = CBOR.Value([
            CBOR.Value(Data("22".utf8)): CBOR.Value(0),
            CBOR.Value(Data("3".utf8)): CBOR.Value(0),
            CBOR.Value(Data("111".utf8)): CBOR.Value(0),
        ])
        try assertCBOREncode(expectedHex: "a3413300423232004331313100", value: value)
    }

    @Test("Canonical key ordering - byte strings with numbers") func testKeyOrderByteStringsNumbers() throws {
        let value = CBOR.Value([
            CBOR.Value(Data("001".utf8)): CBOR.Value(0),
            CBOR.Value(Data("003".utf8)): CBOR.Value(0),
            CBOR.Value(Data("002".utf8)): CBOR.Value(0),
        ])
        try assertCBOREncode(expectedHex: "a3433030310043303032004330303300", value: value)
    }

    @Test("Canonical key ordering - boolean keys") func testKeyOrderBooleans() throws {
        let value: CBOR.Value = [true: 0, false: 0]
        try assertCBOREncode(expectedHex: "a2f400f500", value: value)
    }

    @Test("Canonical key ordering - string keys by length") func testKeyOrderStringsByLength() throws {
        let value: CBOR.Value = ["1": 0, "100": 0, "10": 0]
        try assertCBOREncode(expectedHex: "a3613100623130006331303000", value: value)
    }

    // MARK: - Error Tests

    @Test("Decode with extraneous data throws error") func testExtraneousData() throws {
        let data = Data(hexString: "0001")!  // Valid integer 0, followed by extra byte
        #expect(throws: CBOR.Error.extraneousData) {
            _ = try data.decode() as Int?
        }
    }

    @Test("Decode unexpected end of data throws error") func testUnexpectedEndOfData() throws {
        let data = Data(hexString: "18")!  // Integer with 1-byte value but missing value byte
        #expect(throws: CBOR.Error.unexpectedEndOfData) {
            _ = try data.decode() as Int?
        }
    }

    @Test("Decode invalid UTF-8 throws error") func testInvalidUTF8() throws {
        // CBOR text string with invalid UTF-8 bytes
        let data = Data(hexString: "62ff80")!  // Text string of length 2 with invalid UTF-8
        #expect(throws: CBOR.Error.invalidUTF8) {
            _ = try data.decode() as String?
        }
    }

    // MARK: - Accessor Tests

    @Test("Integer accessor returns correct value") func testIntegerAccessor() throws {
        let value: CBOR.Value = 42
        #expect(value.intValue == 42)
        #expect(value.stringValue == nil)
    }

    @Test("Negative integer accessor returns correct value") func testNegativeIntegerAccessor() throws {
        let value: CBOR.Value = -100
        #expect(value.intValue == -100)
    }

    @Test("String accessor returns correct value") func testStringAccessor() throws {
        let value: CBOR.Value = "hello"
        #expect(value.stringValue == "hello")
        #expect(value.intValue == nil)
    }

    @Test("Data accessor returns correct value") func testDataAccessor() throws {
        let data = Data([1, 2, 3, 4])
        let value: CBOR.Value = .byteString(data)
        #expect(value.dataValue == data)
        #expect(value.stringValue == nil)
    }

    @Test("Array accessor returns correct value") func testArrayAccessor() throws {
        let value: CBOR.Value = [1, 2, 3]
        #expect(value.arrayValue?.count == 3)
        #expect(value.mapValue == nil)
    }

    @Test("Map accessor returns correct value") func testMapAccessor() throws {
        let value: CBOR.Value = [1: "one", 2: "two"]
        #expect(value.mapValue?.count == 2)
        #expect(value.arrayValue == nil)
    }

    @Test("Boolean accessor returns correct value") func testBooleanAccessor() throws {
        let trueValue: CBOR.Value = true
        let falseValue: CBOR.Value = false

        #expect(trueValue.boolValue == true)
        #expect(falseValue.boolValue == false)
        #expect(trueValue.intValue == nil)
    }

    @Test("Null accessor returns correct value") func testNullAccessor() throws {
        let value: CBOR.Value = .null
        #expect(value.isNull == true)
        #expect(value.boolValue == nil)
    }

    @Test("Array subscript returns correct element") func testArraySubscript() throws {
        let value: CBOR.Value = [1, 2, 3]
        #expect(value[0] == 1)
        #expect(value[1] == 2)
        #expect(value[2] == 3)
        #expect(value[3] == nil)
        #expect(value[-1] == nil)
    }

    @Test("Map integer key subscript returns correct value") func testMapIntegerSubscript() throws {
        let value: CBOR.Value = [1: "one", 2: "two"]
        #expect(value[1]?.stringValue == "one")
        #expect(value[2]?.stringValue == "two")
        #expect(value[3] == nil)
    }

    // MARK: - Round-trip Tests

    @Test("Round-trip encode/decode preserves value") func testRoundTrip() throws {
        let original: CBOR.Value = [
            "name": "Alice",
            "age": 30,
            "active": true,
            "tags": ["swift", "cbor"],
            "metadata": [
                "created": 1_234_567_890,
                "updated": nil,
            ],
        ]

        let encoded = try original.encode()
        let decoded = try encoded.decode() as CBOR.Value?

        #expect(decoded == original)
    }

    // MARK: - Boundary Value Tests

    @Test(
        "Integer encoding boundaries",
        arguments: [
            // Inline (0-23) vs 1-byte
            ("17", CBOR.Value(23)),
            ("1818", CBOR.Value(24)),
            // 1-byte vs 2-bytes
            ("18ff", CBOR.Value(255)),
            ("190100", CBOR.Value(256)),
            // 2-bytes vs 4-bytes
            ("19ffff", CBOR.Value(65535)),
            ("1a00010000", CBOR.Value(65536)),
            // 4-bytes vs 8-bytes
            ("1affffffff", CBOR.Value.unsignedInt(UInt64(UInt32.max))),
            ("1b0000000100000000", CBOR.Value.unsignedInt(UInt64(UInt32.max) + 1)),
        ]
    )
    func testIntegerBoundaries(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncodeAndDecode(expectedHex: expectedHex, value: value)
    }

    // MARK: - Large String Tests

    @Test(
        "String length encoding boundaries",
        arguments: [
            // Byte strings: length 24 (1-byte), length 256 (2-bytes)
            ("5818" + String(repeating: "42", count: 24), CBOR.Value.byteString(Data(repeating: 0x42, count: 24))),
            ("590100" + String(repeating: "42", count: 256), CBOR.Value.byteString(Data(repeating: 0x42, count: 256))),
            // Text strings: length 24 (1-byte), length 256 (2-bytes)
            ("7818" + String(repeating: "41", count: 24), CBOR.Value.textString(String(repeating: "A", count: 24))),
            ("790100" + String(repeating: "41", count: 256), CBOR.Value.textString(String(repeating: "A", count: 256))),
        ]
    )
    func testStringLengthBoundaries(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncodeAndDecode(expectedHex: expectedHex, value: value)
    }

    // MARK: - Negative Integer Encoding Tests

    @Test(
        "Negative integer encoding",
        arguments: [
            // -1 - n formula: -1 → 0, -24 → 23, -25 → 24, -256 → 255, -257 → 256
            ("20", CBOR.Value(-1)),  // Inline
            ("37", CBOR.Value(-24)),  // Inline boundary
            ("3818", CBOR.Value(-25)),  // 1-byte follows
            ("38ff", CBOR.Value(-256)),  // 1-byte max
            ("390100", CBOR.Value(-257)),  // 2-bytes
        ]
    )
    func testNegativeIntegerEncoding(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncodeAndDecode(expectedHex: expectedHex, value: value)
    }

    // MARK: - Protocol Conformance Tests

    @Test("CBOR.Encodable conformance for standard types") func testEncodableConformance() throws {
        let intValue = 42.cbor()
        #expect(intValue.intValue == 42)

        let stringValue = "hello".cbor()
        #expect(stringValue.stringValue == "hello")

        let boolValue = true.cbor()
        #expect(boolValue.boolValue == true)

        let dataValue = Data([1, 2, 3]).cbor()
        #expect(dataValue.dataValue == Data([1, 2, 3]))
    }

    @Test("CBOR.Decodable conformance for standard types") func testDecodableConformance() throws {
        let intCBOR: CBOR.Value = 42
        let intValue = Int(cbor: intCBOR)
        #expect(intValue == 42)

        let stringCBOR: CBOR.Value = "hello"
        let stringValue = String(cbor: stringCBOR)
        #expect(stringValue == "hello")

        let boolCBOR: CBOR.Value = true
        let boolValue = Bool(cbor: boolCBOR)
        #expect(boolValue == true)

        let dataCBOR: CBOR.Value = .byteString(Data([1, 2, 3]))
        let dataValue = Data(cbor: dataCBOR)
        #expect(dataValue == Data([1, 2, 3]))
    }

    // MARK: - Helper Methods

    private func assertCBOREncode(expectedHex: String, value: CBOR.Value) throws {
        let encoded = try value.encode()
        let expectedData = Data(hexString: expectedHex)!

        #expect(
            encoded == expectedData,
            "Expected to encode to \(expectedHex), but got \(encoded.hexString)"
        )
    }

    private func assertCBORDecode(expectedValue: CBOR.Value, cborHex: String) throws {
        let data = Data(hexString: cborHex)!
        let decoded = try data.decode() as CBOR.Value?

        #expect(
            decoded == expectedValue,
            "Expected to decode into \(expectedValue), but got \(decoded ?? .null)"
        )
    }

    private func assertCBOREncodeAndDecode(expectedHex: String, value: CBOR.Value) throws {
        try assertCBOREncode(expectedHex: expectedHex, value: value)
        try assertCBORDecode(expectedValue: value, cborHex: expectedHex)
    }
}

// MARK: - Data Extension for Hex String Conversion

extension Data {
    fileprivate init?(hexString: String) {
        let cleanHex = hexString.replacingOccurrences(of: " ", with: "")
        guard cleanHex.count % 2 == 0 else { return nil }

        var data = Data(capacity: cleanHex.count / 2)
        var index = cleanHex.startIndex

        while index < cleanHex.endIndex {
            let nextIndex = cleanHex.index(index, offsetBy: 2)
            let byteString = cleanHex[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }

    fileprivate var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
