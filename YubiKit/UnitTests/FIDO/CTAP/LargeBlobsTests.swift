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

/// Unit tests for CTAP2 LargeBlobs public types.
@Suite("CTAP2 LargeBlobs Tests")
struct LargeBlobsTests {

    // MARK: - BlobArray CBOR Tests

    @Test("Empty BlobArray encodes to empty CBOR array")
    func testEmptyBlobArrayCBOR() {
        let blobArray = CTAP2.LargeBlobs.BlobArray()
        let cbor = blobArray.cbor()

        guard case .array(let array) = cbor else {
            Issue.record("Expected array CBOR value")
            return
        }
        #expect(array.isEmpty)
    }

    @Test("BlobArray with entries encodes correctly")
    func testBlobArrayWithEntriesCBOR() {
        let entry = CTAP2.LargeBlobs.BlobArray.Entry(
            ciphertext: Data([0x01, 0x02, 0x03]),
            nonce: Data(repeating: 0x00, count: 12),
            origSize: 100
        )
        let blobArray = CTAP2.LargeBlobs.BlobArray(entries: [entry])
        let cbor = blobArray.cbor()

        guard case .array(let array) = cbor else {
            Issue.record("Expected array CBOR value")
            return
        }
        #expect(array.count == 1)
    }

    @Test("BlobArray CBOR roundtrip")
    func testBlobArrayCBORRoundtrip() {
        let entry1 = CTAP2.LargeBlobs.BlobArray.Entry(
            ciphertext: Data([0x01, 0x02, 0x03]),
            nonce: Data(repeating: 0xAA, count: 12),
            origSize: 50
        )
        let entry2 = CTAP2.LargeBlobs.BlobArray.Entry(
            ciphertext: Data([0x04, 0x05, 0x06, 0x07]),
            nonce: Data(repeating: 0xBB, count: 12),
            origSize: 200
        )
        let original = CTAP2.LargeBlobs.BlobArray(entries: [entry1, entry2])

        // Encode and decode
        let encoded = original.cbor().encode()
        guard let decoded: CTAP2.LargeBlobs.BlobArray = try? encoded.decode() else {
            Issue.record("Failed to decode BlobArray")
            return
        }

        #expect(decoded.entries.count == 2)
        #expect(decoded.entries[0].ciphertext == entry1.ciphertext)
        #expect(decoded.entries[0].nonce == entry1.nonce)
        #expect(decoded.entries[0].origSize == entry1.origSize)
        #expect(decoded.entries[1].ciphertext == entry2.ciphertext)
        #expect(decoded.entries[1].nonce == entry2.nonce)
        #expect(decoded.entries[1].origSize == entry2.origSize)
    }

    // MARK: - BlobArray Entry CBOR Tests

    @Test("Entry encodes with correct CBOR keys")
    func testEntryCBORKeys() {
        let entry = CTAP2.LargeBlobs.BlobArray.Entry(
            ciphertext: Data([0x01]),
            nonce: Data(repeating: 0x00, count: 12),
            origSize: 1
        )
        let cbor = entry.cbor()

        guard case .map(let map) = cbor else {
            Issue.record("Expected map CBOR value")
            return
        }

        // Keys should be 0x01, 0x02, 0x03
        #expect(map[.int(0x01)] != nil)  // ciphertext
        #expect(map[.int(0x02)] != nil)  // nonce
        #expect(map[.int(0x03)] != nil)  // origSize
    }

    @Test("Entry CBOR roundtrip")
    func testEntryCBORRoundtrip() {
        let original = CTAP2.LargeBlobs.BlobArray.Entry(
            ciphertext: Data([0xDE, 0xAD, 0xBE, 0xEF]),
            nonce: Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]),
            origSize: 12345
        )

        let encoded = original.cbor().encode()
        guard let cbor: CBOR.Value = try? encoded.decode() else {
            Issue.record("Failed to decode CBOR")
            return
        }

        guard let decoded = CTAP2.LargeBlobs.BlobArray.Entry(cbor: cbor) else {
            Issue.record("Failed to parse Entry from CBOR")
            return
        }

        #expect(decoded.ciphertext == original.ciphertext)
        #expect(decoded.nonce == original.nonce)
        #expect(decoded.origSize == original.origSize)
    }

    // MARK: - LargeBlobKey Extension Tests

    @Test("LargeBlobKey can create MakeCredential input")
    func testLargeBlobKeyMakeCredentialInput() {
        let ext = CTAP2.Extension.LargeBlobKey()
        let input = ext.makeCredential.input()
        let encoded = input.encode()
        #expect(encoded[.largeBlobKey] != nil)
    }

    @Test("LargeBlobKey can create GetAssertion input")
    func testLargeBlobKeyGetAssertionInput() {
        let ext = CTAP2.Extension.LargeBlobKey()
        let input = ext.getAssertion.input()
        let encoded = input.encode()
        #expect(encoded[.largeBlobKey] != nil)
    }
}
