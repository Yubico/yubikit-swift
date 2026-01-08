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

import CryptoKit
import Foundation
import Testing

@testable import YubiKit

/// Unit tests for CTAP2 LargeBlobs operations.
@Suite("CTAP2 LargeBlobs Tests")
struct LargeBlobsTests {

    // MARK: - Checksum Tests

    @Test("Checksum produces 16-byte SHA-256 truncated hash")
    func testChecksumLength() {
        let data = Data("test data".utf8)
        let checksum = CTAP2.LargeBlobs.checksum(data)
        #expect(checksum.count == 16)
    }

    @Test("Checksum is deterministic")
    func testChecksumDeterministic() {
        let data = Data("test data".utf8)
        let checksum1 = CTAP2.LargeBlobs.checksum(data)
        let checksum2 = CTAP2.LargeBlobs.checksum(data)
        #expect(checksum1 == checksum2)
    }

    @Test("Checksum produces different outputs for different inputs")
    func testChecksumDifferentInputs() {
        let data1 = Data("data one".utf8)
        let data2 = Data("data two".utf8)
        let checksum1 = CTAP2.LargeBlobs.checksum(data1)
        let checksum2 = CTAP2.LargeBlobs.checksum(data2)
        #expect(checksum1 != checksum2)
    }

    @Test("Checksum of empty data is first 16 bytes of SHA-256 of empty")
    func testChecksumEmpty() {
        let data = Data()
        let checksum = CTAP2.LargeBlobs.checksum(data)
        // SHA-256 of empty string starts with e3b0c44298fc1c14...
        let expected = Data([
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        ])
        #expect(checksum == expected)
    }

    // MARK: - Compression Tests

    @Test("Compression and decompression roundtrip")
    func testCompressionRoundtrip() throws {
        let original = Data("Hello, World! This is test data for compression.".utf8)
        let compressed = try CTAP2.LargeBlobs.compress(original)
        let decompressed = try CTAP2.LargeBlobs.decompress(compressed, originalSize: original.count)
        #expect(decompressed == original)
    }

    @Test("Compression reduces size for repetitive data")
    func testCompressionReducesSize() throws {
        let original = Data(repeating: 0x41, count: 1000)  // 1000 'A' bytes
        let compressed = try CTAP2.LargeBlobs.compress(original)
        #expect(compressed.count < original.count)
    }

    @Test("Compression handles small data")
    func testCompressionSmallData() throws {
        let original = Data([0x01, 0x02, 0x03])
        let compressed = try CTAP2.LargeBlobs.compress(original)
        let decompressed = try CTAP2.LargeBlobs.decompress(compressed, originalSize: original.count)
        #expect(decompressed == original)
    }

    @Test("Decompression fails with wrong original size")
    func testDecompressionWrongSize() throws {
        let original = Data("test data".utf8)
        let compressed = try CTAP2.LargeBlobs.compress(original)

        do {
            _ = try CTAP2.LargeBlobs.decompress(compressed, originalSize: original.count + 10)
            Issue.record("Expected error to be thrown")
        } catch {
            guard case .dataProcessingError = error else {
                Issue.record("Expected dataProcessingError, got \(error)")
                return
            }
        }
    }

    // MARK: - Encryption/Decryption Tests

    @Test("Encryption and decryption roundtrip")
    func testEncryptionRoundtrip() throws {
        let plaintext = Data("Secret blob data for credential".utf8)
        let key = Data(repeating: 0x42, count: 32)

        let entry = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: key)
        let decrypted = try CTAP2.LargeBlobs.decrypt(entry: entry, key: key)

        #expect(decrypted == plaintext)
    }

    @Test("Encryption produces different ciphertext each time (random nonce)")
    func testEncryptionRandomNonce() throws {
        let plaintext = Data("test data".utf8)
        let key = Data(repeating: 0x42, count: 32)

        let entry1 = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: key)
        let entry2 = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: key)

        #expect(entry1.nonce != entry2.nonce)
        #expect(entry1.ciphertext != entry2.ciphertext)
    }

    @Test("Encryption entry has correct nonce length")
    func testEncryptionNonceLength() throws {
        let plaintext = Data("test".utf8)
        let key = Data(repeating: 0x42, count: 32)

        let entry = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: key)
        #expect(entry.nonce.count == 12)
    }

    @Test("Encryption entry has correct original size")
    func testEncryptionOriginalSize() throws {
        let plaintext = Data("test data with known size".utf8)
        let key = Data(repeating: 0x42, count: 32)

        let entry = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: key)
        #expect(entry.origSize == UInt64(plaintext.count))
    }

    @Test("Encryption rejects invalid key length")
    func testEncryptionInvalidKeyLength() {
        let plaintext = Data("test".utf8)
        let shortKey = Data(repeating: 0x42, count: 16)

        do {
            _ = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: shortKey)
            Issue.record("Expected error to be thrown")
        } catch {
            guard case .illegalArgument = error else {
                Issue.record("Expected illegalArgument, got \(error)")
                return
            }
        }
    }

    @Test("Decryption fails with wrong key")
    func testDecryptionWrongKey() throws {
        let plaintext = Data("secret data".utf8)
        let key1 = Data(repeating: 0x42, count: 32)
        let key2 = Data(repeating: 0x43, count: 32)

        let entry = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: key1)

        do {
            _ = try CTAP2.LargeBlobs.decrypt(entry: entry, key: key2)
            Issue.record("Expected error to be thrown")
        } catch {
            guard case .dataProcessingError = error else {
                Issue.record("Expected dataProcessingError, got \(error)")
                return
            }
        }
    }

    @Test("Decryption rejects invalid key length")
    func testDecryptionInvalidKeyLength() throws {
        let plaintext = Data("test".utf8)
        let validKey = Data(repeating: 0x42, count: 32)
        let shortKey = Data(repeating: 0x42, count: 16)

        let entry = try CTAP2.LargeBlobs.encrypt(data: plaintext, key: validKey)

        do {
            _ = try CTAP2.LargeBlobs.decrypt(entry: entry, key: shortKey)
            Issue.record("Expected error to be thrown")
        } catch {
            guard case .illegalArgument = error else {
                Issue.record("Expected illegalArgument, got \(error)")
                return
            }
        }
    }

    // MARK: - Write Auth Message Tests

    @Test("Write auth message has correct format")
    func testWriteAuthMessageFormat() {
        let fragment = Data([0x01, 0x02, 0x03, 0x04])
        let offset: UInt = 0

        let message = CTAP2.LargeBlobs.writeAuthMessage(fragment: fragment, offset: offset)

        // Message format: 0xFF*32 || 0x0C || 0x00 || uint32LE(offset) || SHA256(fragment)
        #expect(message.count == 32 + 2 + 4 + 32)  // 70 bytes total

        // First 32 bytes should be 0xFF
        #expect(message.prefix(32) == Data(repeating: 0xFF, count: 32))

        // Next 2 bytes: command (0x0C) and subcommand padding (0x00)
        #expect(message[32] == 0x0C)
        #expect(message[33] == 0x00)

        // Next 4 bytes: offset as uint32LE
        #expect(message[34] == 0x00)
        #expect(message[35] == 0x00)
        #expect(message[36] == 0x00)
        #expect(message[37] == 0x00)

        // Last 32 bytes: SHA256(fragment)
        let expectedHash = Data(SHA256.hash(data: fragment))
        #expect(message.suffix(32) == expectedHash)
    }

    @Test("Write auth message encodes offset correctly")
    func testWriteAuthMessageOffset() {
        let fragment = Data([0x01])
        let offset: UInt = 0x1234_5678

        let message = CTAP2.LargeBlobs.writeAuthMessage(fragment: fragment, offset: offset)

        // Offset should be little-endian at bytes 34-37
        #expect(message[34] == 0x78)
        #expect(message[35] == 0x56)
        #expect(message[36] == 0x34)
        #expect(message[37] == 0x12)
    }

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

    @Test("LargeBlobKey extension identifier is largeBlobKey")
    func testLargeBlobKeyIdentifier() {
        // Static identifier on the type
        #expect(CTAP2.Extension.LargeBlobKey.identifier == .largeBlobKey)
    }

    @Test("LargeBlobKey can create MakeCredential input")
    func testLargeBlobKeyMakeCredentialInput() {
        let ext = CTAP2.Extension.LargeBlobKey()
        // This should compile and return a valid Input type
        let input = ext.makeCredential.input()
        // Verify it can be encoded (internal method, but proves it's properly formed)
        let encoded = input.encode()
        #expect(encoded[.largeBlobKey] != nil)
    }

    @Test("LargeBlobKey can create GetAssertion input")
    func testLargeBlobKeyGetAssertionInput() {
        let ext = CTAP2.Extension.LargeBlobKey()
        // This should compile and return a valid Input type
        let input = ext.getAssertion.input()
        // Verify it can be encoded (internal method, but proves it's properly formed)
        let encoded = input.encode()
        #expect(encoded[.largeBlobKey] != nil)
    }

    // MARK: - ReadParameters CBOR Tests

    @Test("ReadParameters encodes with correct CBOR keys")
    func testReadParametersCBOR() {
        let params = CTAP2.LargeBlobs.ReadParameters(get: 100, offset: 50)
        let cbor = params.cbor()

        guard case .map(let map) = cbor else {
            Issue.record("Expected map CBOR value")
            return
        }

        // Key 0x01 = get, Key 0x03 = offset
        #expect(map[.int(0x01)] != nil)
        #expect(map[.int(0x03)] != nil)
    }

    // MARK: - WriteParameters CBOR Tests

    @Test("WriteParameters encodes with correct CBOR keys including length")
    func testWriteParametersWithLengthCBOR() {
        let params = CTAP2.LargeBlobs.WriteParameters(
            set: Data([0x01, 0x02]),
            offset: 0,
            length: 100,
            pinUVAuthParam: Data(repeating: 0xAA, count: 16),
            pinUVAuthProtocol: .v1
        )
        let cbor = params.cbor()

        guard case .map(let map) = cbor else {
            Issue.record("Expected map CBOR value")
            return
        }

        // Key 0x02 = set, 0x03 = offset, 0x04 = length, 0x05 = pinUvAuthParam, 0x06 = pinUvAuthProtocol
        #expect(map[.int(0x02)] != nil)
        #expect(map[.int(0x03)] != nil)
        #expect(map[.int(0x04)] != nil)
        #expect(map[.int(0x05)] != nil)
        #expect(map[.int(0x06)] != nil)
    }

    @Test("WriteParameters encodes without length when nil")
    func testWriteParametersWithoutLengthCBOR() {
        let params = CTAP2.LargeBlobs.WriteParameters(
            set: Data([0x01, 0x02]),
            offset: 100,
            length: nil,
            pinUVAuthParam: Data(repeating: 0xAA, count: 16),
            pinUVAuthProtocol: .v2
        )
        let cbor = params.cbor()

        guard case .map(let map) = cbor else {
            Issue.record("Expected map CBOR value")
            return
        }

        // Key 0x04 = length should NOT be present
        #expect(map[.int(0x02)] != nil)
        #expect(map[.int(0x03)] != nil)
        #expect(map[.int(0x04)] == nil)
        #expect(map[.int(0x05)] != nil)
        #expect(map[.int(0x06)] != nil)
    }
}
