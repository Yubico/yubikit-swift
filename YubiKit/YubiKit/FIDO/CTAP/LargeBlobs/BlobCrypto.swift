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

import Compression
import CryptoKit
import Foundation

// MARK: - Blob Crypto Operations

extension CTAP2.LargeBlobs {

    /// Length of the checksum appended to the serialized blob array.
    static let checksumLength = 16

    /// Nonce length for AES-GCM encryption.
    private static let nonceLength = 12

    // MARK: - Checksum

    /// Computes the SHA-256 checksum truncated to 16 bytes.
    ///
    /// - Parameter data: The data to checksum.
    /// - Returns: The first 16 bytes of the SHA-256 hash.
    static func checksum(_ data: Data) -> Data {
        let hash = SHA256.hash(data: data)
        return Data(hash.prefix(checksumLength))
    }

    // MARK: - Compression

    /// Compresses data using DEFLATE (raw, no zlib header).
    ///
    /// - Parameter data: The data to compress.
    /// - Returns: The compressed data.
    /// - Throws: `CTAP2.SessionError` if compression fails.
    static func compress(_ data: Data) throws(CTAP2.SessionError) -> Data {
        guard !data.isEmpty else {
            return Data()
        }

        // Allocate destination buffer (worst case: slightly larger than input)
        let destinationSize = data.count + 64
        var destinationBuffer = Data(count: destinationSize)

        let compressedSize = data.withUnsafeBytes { srcBuffer in
            destinationBuffer.withUnsafeMutableBytes { dstBuffer in
                compression_encode_buffer(
                    dstBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    dstBuffer.count,
                    srcBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    srcBuffer.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }

        guard compressedSize > 0 else {
            throw .dataProcessingError("DEFLATE compression failed", source: .here())
        }

        return destinationBuffer.prefix(compressedSize)
    }

    /// Decompresses DEFLATE data.
    ///
    /// - Parameters:
    ///   - data: The compressed data.
    ///   - originalSize: The expected original size.
    /// - Returns: The decompressed data.
    /// - Throws: `CTAP2.SessionError` if decompression fails or size doesn't match.
    static func decompress(_ data: Data, originalSize: Int) throws(CTAP2.SessionError) -> Data {
        guard originalSize > 0 else {
            return Data()
        }
        guard !data.isEmpty else {
            throw .dataProcessingError("Cannot decompress empty data", source: .here())
        }

        // Allocate destination buffer for original size
        var destinationBuffer = Data(count: originalSize)

        let decompressedSize = data.withUnsafeBytes { srcBuffer in
            destinationBuffer.withUnsafeMutableBytes { dstBuffer in
                compression_decode_buffer(
                    dstBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    dstBuffer.count,
                    srcBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    srcBuffer.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }

        guard decompressedSize == originalSize else {
            throw .dataProcessingError(
                "DEFLATE decompression size mismatch: expected \(originalSize), got \(decompressedSize)",
                source: .here()
            )
        }

        return destinationBuffer
    }

    // MARK: - Encryption

    /// Encrypts data for storage in the large blob array.
    ///
    /// The data is first compressed using DEFLATE, then encrypted with AES-256-GCM.
    /// The associated data is `"blob" || uint64LE(originalSize)`.
    ///
    /// - Parameters:
    ///   - data: The plaintext data to encrypt.
    ///   - key: The 32-byte largeBlobKey.
    /// - Returns: A blob entry containing the encrypted data.
    /// - Throws: `CTAP2.SessionError` if encryption fails.
    static func encrypt(data: Data, key: Data) throws(CTAP2.SessionError) -> BlobArray.Entry {
        guard key.count == 32 else {
            throw .illegalArgument("largeBlobKey must be 32 bytes", source: .here())
        }

        let originalSize = data.count

        // Compress the data
        let compressed = try compress(data)

        // Generate random nonce
        var nonce = Data(count: nonceLength)
        let status = nonce.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, nonceLength, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw .dataProcessingError("Failed to generate random nonce", source: .here())
        }

        // Build associated data: "blob" || uint64LE(originalSize)
        var ad = Data("blob".utf8)
        var sizeLE = UInt64(originalSize).littleEndian
        ad.append(Data(bytes: &sizeLE, count: 8))

        // Encrypt with AES-256-GCM
        do {
            let symmetricKey = SymmetricKey(data: key)
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let sealedBox = try AES.GCM.seal(compressed, using: symmetricKey, nonce: gcmNonce, authenticating: ad)

            // ciphertext includes the auth tag
            guard let ciphertext = sealedBox.combined?.dropFirst(nonceLength) else {
                throw CTAP2.SessionError.dataProcessingError("AES-GCM encryption failed", source: .here())
            }

            return BlobArray.Entry(
                ciphertext: Data(ciphertext),
                nonce: nonce,
                origSize: originalSize
            )
        } catch let error as CTAP2.SessionError {
            throw error
        } catch {
            throw .dataProcessingError("AES-GCM encryption failed: \(error)", source: .here())
        }
    }

    /// Decrypts a blob entry.
    ///
    /// - Parameters:
    ///   - entry: The blob entry to decrypt.
    ///   - key: The 32-byte largeBlobKey.
    /// - Returns: The decrypted and decompressed data.
    /// - Throws: `CTAP2.SessionError` if decryption fails.
    static func decrypt(entry: BlobArray.Entry, key: Data) throws(CTAP2.SessionError) -> Data {
        guard key.count == 32 else {
            throw .illegalArgument("largeBlobKey must be 32 bytes", source: .here())
        }

        guard entry.nonce.count == nonceLength else {
            throw .dataProcessingError("Invalid nonce length", source: .here())
        }

        // Build associated data: "blob" || uint64LE(originalSize)
        var ad = Data("blob".utf8)
        var sizeLE = UInt64(entry.origSize).littleEndian
        ad.append(Data(bytes: &sizeLE, count: 8))

        // Decrypt with AES-256-GCM
        let compressed: Data
        do {
            let symmetricKey = SymmetricKey(data: key)

            // Reconstruct sealed box: nonce || ciphertext (includes tag)
            let combined = entry.nonce + entry.ciphertext
            let sealedBox = try AES.GCM.SealedBox(combined: combined)

            compressed = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: ad)
        } catch {
            throw .dataProcessingError("AES-GCM decryption failed: \(error)", source: .here())
        }

        // Decompress
        return try decompress(compressed, originalSize: entry.origSize)
    }

    // MARK: - PIN Auth Message

    /// Computes the PIN/UV auth message for write operations.
    ///
    /// Message format: `0xFF*32 || 0x0C || 0x00 || uint32LE(offset) || SHA256(fragment)`
    ///
    /// - Parameters:
    ///   - fragment: The data fragment being written.
    ///   - offset: The byte offset for this fragment.
    /// - Returns: The message to authenticate.
    static func writeAuthMessage(fragment: Data, offset: UInt) -> Data {
        var message = Data(repeating: 0xFF, count: 32)
        message.append(contentsOf: [0x0C, 0x00])  // Command + subcommand padding
        var offsetLE = UInt32(offset).littleEndian
        message.append(Data(bytes: &offsetLE, count: 4))
        message.append(Data(SHA256.hash(data: fragment)))
        return message
    }
}
