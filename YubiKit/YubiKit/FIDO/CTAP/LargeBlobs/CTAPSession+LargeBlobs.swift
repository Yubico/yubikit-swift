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

// MARK: - LargeBlobs Session Methods

extension CTAP2.Session {

    // maxFragmentLength = maxMsgSize - 64, as per spec.
    private static let maxFragmentLengthOverhead = 64

    // MARK: - Support Check

    /// Checks if the authenticator supports large blobs.
    ///
    /// - Returns: `true` if the authenticator supports the `largeBlobs` option.
    public func supportsLargeBlobs() async throws(CTAP2.SessionError) -> Bool {
        let info = try await getInfo()
        return info.options.largeBlobs == true
    }

    // MARK: - Internal Array Operations

    // Reads the entire large blob array with checksum validation.
    func readBlobArray() async throws(CTAP2.SessionError) -> CTAP2.LargeBlobs.BlobArray {
        let info = try await getInfo()
        let maxFragment = Int(info.maxMsgSize) - Self.maxFragmentLengthOverhead

        // Read all fragments
        var data = Data()
        var offset: UInt = 0
        while true {
            let fragment = try await readLargeBlobFragment(get: UInt(maxFragment), offset: offset)
            data.append(fragment)
            if fragment.count < maxFragment {
                break
            }
            offset += UInt(fragment.count)
        }

        // Validate minimum size (at least checksum)
        guard data.count >= Self.checksumLength else {
            throw .ctapError(.integrityFailure, source: .here())
        }

        // Split data and checksum
        let content = Data(data.dropLast(Self.checksumLength))
        let checksum = Data(data.suffix(Self.checksumLength))

        // Validate checksum
        let expectedChecksum = self.checksum(content)
        guard checksum == expectedChecksum else {
            throw .ctapError(.integrityFailure, source: .here())
        }

        // Parse CBOR array
        guard !content.isEmpty else {
            // Empty array case (just checksum of empty array)
            return CTAP2.LargeBlobs.BlobArray()
        }

        guard let blobArray: CTAP2.LargeBlobs.BlobArray = try? content.decode() else {
            throw .responseParseError("Failed to parse large blob array", source: .here())
        }

        return blobArray
    }

    // Writes the entire large blob array with automatic fragmentation.
    func writeBlobArray(
        _ blobArray: CTAP2.LargeBlobs.BlobArray,
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
        let info = try await getInfo()
        let maxFragment = Int(info.maxMsgSize) - Self.maxFragmentLengthOverhead

        // Encode array and append checksum
        let encoded = blobArray.cbor().encode()
        var data = encoded
        data.append(checksum(encoded))

        // Check against max size if available
        if let maxSize = info.maxSerializedLargeBlobArray {
            guard data.count <= Int(maxSize) else {
                throw .ctapError(.largeBlobStorageFull, source: .here())
            }
        }

        // Write in fragments
        let totalLength = UInt(data.count)
        var offset: UInt = 0

        while offset < totalLength {
            let fragmentSize = min(maxFragment, Int(totalLength - offset))
            let fragment = data.subdata(in: Int(offset)..<(Int(offset) + fragmentSize))

            // length is only sent on first fragment
            let length: UInt? = offset == 0 ? totalLength : nil

            try await writeLargeBlobFragment(
                set: fragment,
                offset: offset,
                length: length,
                pinToken: pinToken
            )

            offset += UInt(fragmentSize)
        }
    }

    // MARK: - Credential Blob Operations

    /// Gets a decrypted blob for a credential.
    ///
    /// Reads the entire blob array and attempts to decrypt each entry
    /// with the provided key until a match is found.
    ///
    /// - Parameter key: The 32-byte largeBlobKey for the credential.
    /// - Returns: The decrypted blob data, or `nil` if no matching blob is found.
    /// - Throws: `CTAP2.SessionError` if reading fails.
    public func getBlob(key: Data) async throws(CTAP2.SessionError) -> Data? {
        let blobArray = try await readBlobArray()

        // Try to decrypt each entry with the key
        for entry in blobArray.entries {
            do {
                let decrypted = try decrypt(entry: entry, key: key)
                return decrypted
            } catch {
                // Wrong key for this entry, try next
                continue
            }
        }

        return nil
    }

    /// Stores an encrypted blob for a credential.
    ///
    /// Reads the current blob array, removes any existing blobs for this key,
    /// adds the new encrypted blob, and writes the array back.
    ///
    /// - Parameters:
    ///   - key: The 32-byte largeBlobKey for the credential.
    ///   - data: The data to store.
    ///   - pinToken: PIN/UV auth token with largeBlobWrite permission.
    /// - Throws: `CTAP2.SessionError` if the operation fails.
    public func putBlob(
        key: Data,
        data: Data,
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
        var blobArray = try await readBlobArray()

        // Remove existing entries for this key
        blobArray.entries.removeAll { entry in
            do {
                _ = try decrypt(entry: entry, key: key)
                return true  // Successfully decrypted = same key, remove it
            } catch {
                return false  // Different key, keep it
            }
        }

        // Encrypt and add new entry
        let newEntry = try encrypt(data: data, key: key)
        blobArray.entries.append(newEntry)

        // Write back
        try await writeBlobArray(blobArray, pinToken: pinToken)
    }

    /// Deletes any blobs for a credential.
    ///
    /// Reads the current blob array, removes all entries that can be
    /// decrypted with the provided key, and writes the array back.
    ///
    /// - Parameters:
    ///   - key: The 32-byte largeBlobKey for the credential.
    ///   - pinToken: PIN/UV auth token with largeBlobWrite permission.
    /// - Throws: `CTAP2.SessionError` if the operation fails.
    public func deleteBlob(
        key: Data,
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
        var blobArray = try await readBlobArray()

        let originalCount = blobArray.entries.count

        // Remove entries for this key
        blobArray.entries.removeAll { entry in
            do {
                _ = try decrypt(entry: entry, key: key)
                return true  // Successfully decrypted = same key, remove it
            } catch {
                return false  // Different key, keep it
            }
        }

        // Only write back if something was removed
        if blobArray.entries.count != originalCount {
            try await writeBlobArray(blobArray, pinToken: pinToken)
        }
    }

    // MARK: - Low-Level Fragment Operations

    // Reads a fragment of the large blob array.
    private func readLargeBlobFragment(
        get: UInt,
        offset: UInt
    ) async throws(CTAP2.SessionError) -> Data {
        let params = ReadParameters(get: get, offset: offset)
        let stream: CTAP2.StatusStream<Response> = await interface.send(
            command: .largeBlobs,
            payload: params
        )
        let response = try await stream.value
        return response.config
    }

    // Writes a fragment to the large blob array.
    private func writeLargeBlobFragment(
        set: Data,
        offset: UInt,
        length: UInt?,
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
        // Compute PIN auth
        let message = writeAuthMessage(fragment: set, offset: offset)
        let pinUVAuthParam = pinToken.authenticate(message: message)

        let params = WriteParameters(
            set: set,
            offset: offset,
            length: length,
            pinUVAuthParam: pinUVAuthParam,
            pinUVAuthProtocol: pinToken.protocolVersion
        )

        let stream: CTAP2.StatusStream<Void> = await interface.send(
            command: .largeBlobs,
            payload: params
        )
        try await stream.value
    }

    // MARK: - Crypto Operations

    // Length of the checksum appended to the serialized blob array.
    private static let checksumLength = 16
    // Nonce length for AES-GCM encryption.
    private static let nonceLength = 12

    // Computes the SHA-256 checksum truncated to 16 bytes.
    private func checksum(_ data: Data) -> Data {
        let hash = SHA256.hash(data: data)
        return Data(hash.prefix(Self.checksumLength))
    }

    // Compresses data using DEFLATE.
    private func compress(_ data: Data) throws(CTAP2.SessionError) -> Data {
        guard !data.isEmpty else {
            return Data()
        }

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

    // Decompresses DEFLATE data.
    private func decompress(_ data: Data, originalSize: Int) throws(CTAP2.SessionError) -> Data {
        guard originalSize > 0 else {
            return Data()
        }
        guard !data.isEmpty else {
            throw .dataProcessingError("Cannot decompress empty data", source: .here())
        }

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

    // Encrypts data for storage in the large blob array.
    private func encrypt(data: Data, key: Data) throws(CTAP2.SessionError) -> CTAP2.LargeBlobs.BlobArray.Entry {
        guard key.count == 32 else {
            throw .illegalArgument("largeBlobKey must be 32 bytes", source: .here())
        }

        let originalSize = data.count
        let compressed = try compress(data)

        // Generate random nonce
        var nonce = Data(count: Self.nonceLength)
        let status = nonce.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, Self.nonceLength, buffer.baseAddress!)
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

            guard let ciphertext = sealedBox.combined?.dropFirst(Self.nonceLength) else {
                throw CTAP2.SessionError.dataProcessingError("AES-GCM encryption failed", source: .here())
            }

            return CTAP2.LargeBlobs.BlobArray.Entry(
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

    // Decrypts a blob entry.
    private func decrypt(entry: CTAP2.LargeBlobs.BlobArray.Entry, key: Data) throws(CTAP2.SessionError) -> Data {
        guard key.count == 32 else {
            throw .illegalArgument("largeBlobKey must be 32 bytes", source: .here())
        }

        guard entry.nonce.count == Self.nonceLength else {
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
            let combined = entry.nonce + entry.ciphertext
            let sealedBox = try AES.GCM.SealedBox(combined: combined)
            compressed = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: ad)
        } catch {
            throw .dataProcessingError("AES-GCM decryption failed: \(error)", source: .here())
        }

        return try decompress(compressed, originalSize: entry.origSize)
    }

    // Computes the PIN/UV auth message for write operations.
    private func writeAuthMessage(fragment: Data, offset: UInt) -> Data {
        var message = Data(repeating: 0xFF, count: 32)
        message.append(contentsOf: [0x0C, 0x00])
        var offsetLE = UInt32(offset).littleEndian
        message.append(Data(bytes: &offsetLE, count: 4))
        message.append(Data(SHA256.hash(data: fragment)))
        return message
    }

    // MARK: - Parameters

    // Parameters for reading from the large blob array.
    private struct ReadParameters: Sendable, CBOR.Encodable {
        let get: UInt
        let offset: UInt

        func cbor() -> CBOR.Value {
            var map: [CBOR.Value: CBOR.Value] = [:]
            map[.int(0x01)] = get.cbor()
            map[.int(0x03)] = offset.cbor()
            return .map(map)
        }
    }

    // Parameters for writing to the large blob array.
    private struct WriteParameters: Sendable, CBOR.Encodable {
        let set: Data
        let offset: UInt
        let length: UInt?
        let pinUVAuthParam: Data
        let pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion

        func cbor() -> CBOR.Value {
            var map: [CBOR.Value: CBOR.Value] = [:]
            map[.int(0x02)] = set.cbor()
            map[.int(0x03)] = offset.cbor()
            if let length {
                map[.int(0x04)] = length.cbor()
            }
            map[.int(0x05)] = pinUVAuthParam.cbor()
            map[.int(0x06)] = pinUVAuthProtocol.cbor()
            return .map(map)
        }
    }

    // Response from the authenticatorLargeBlobs command.
    private struct Response: Sendable, CBOR.Decodable {
        let config: Data

        init?(cbor: CBOR.Value) {
            guard let map = cbor.mapValue,
                let config = map[.int(0x01)]?.dataValue
            else {
                return nil
            }
            self.config = config
        }
    }
}
