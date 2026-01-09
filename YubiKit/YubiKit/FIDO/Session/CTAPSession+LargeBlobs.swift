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

// MARK: - LargeBlobs Session Methods

extension CTAP2.Session {

    /// maxFragmentLength = maxMsgSize - 64, as per spec.
    private static let maxFragmentLengthOverhead = 64

    // MARK: - Support Check

    /// Checks if the authenticator supports large blobs.
    ///
    /// - Returns: `true` if the authenticator supports the `largeBlobs` option.
    public func supportsLargeBlobs() async throws(CTAP2.SessionError) -> Bool {
        let info = try await getInfo()
        return info.options.largeBlobs == true
    }

    // MARK: - Low-Level Fragment Operations

    /// Reads a fragment of the large blob array.
    ///
    /// - Parameters:
    ///   - get: Maximum number of bytes to read.
    ///   - offset: Byte offset to start reading from.
    /// - Returns: The fragment data.
    func readLargeBlobFragment(
        get: UInt,
        offset: UInt
    ) async throws(CTAP2.SessionError) -> Data {
        let params = CTAP2.LargeBlobs.ReadParameters(get: get, offset: offset)
        let stream: CTAP2.StatusStream<CTAP2.LargeBlobs.Response> = await interface.send(
            command: .largeBlobs,
            payload: params
        )
        let response = try await stream.value
        return response.config
    }

    /// Writes a fragment to the large blob array.
    ///
    /// - Parameters:
    ///   - set: The fragment data to write.
    ///   - offset: Byte offset for this fragment.
    ///   - length: Total length (required only for first fragment, nil otherwise).
    ///   - pinToken: PIN/UV auth token with largeBlobWrite permission.
    func writeLargeBlobFragment(
        set: Data,
        offset: UInt,
        length: UInt?,
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
        // Compute PIN auth
        let message = CTAP2.LargeBlobs.writeAuthMessage(fragment: set, offset: offset)
        let pinUVAuthParam = pinToken.authenticate(message: message)

        let params = CTAP2.LargeBlobs.WriteParameters(
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

    // MARK: - High-Level Array Operations

    /// Reads the entire large blob array with checksum validation.
    ///
    /// - Returns: The parsed blob array.
    /// - Throws: `CTAP2.SessionError` if reading fails or checksum is invalid.
    public func readBlobArray() async throws(CTAP2.SessionError) -> CTAP2.LargeBlobs.BlobArray {
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
        guard data.count >= CTAP2.LargeBlobs.checksumLength else {
            throw .ctapError(.integrityFailure, source: .here())
        }

        // Split data and checksum
        let content = Data(data.dropLast(CTAP2.LargeBlobs.checksumLength))
        let checksum = Data(data.suffix(CTAP2.LargeBlobs.checksumLength))

        // Validate checksum
        let expectedChecksum = CTAP2.LargeBlobs.checksum(content)
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

    /// Writes the entire large blob array with automatic fragmentation.
    ///
    /// - Parameters:
    ///   - blobArray: The blob array to write.
    ///   - pinToken: PIN/UV auth token with largeBlobWrite permission.
    /// - Throws: `CTAP2.SessionError` if writing fails.
    public func writeBlobArray(
        _ blobArray: CTAP2.LargeBlobs.BlobArray,
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
        let info = try await getInfo()
        let maxFragment = Int(info.maxMsgSize) - Self.maxFragmentLengthOverhead

        // Encode array and append checksum
        let encoded = blobArray.cbor().encode()
        var data = encoded
        data.append(CTAP2.LargeBlobs.checksum(encoded))

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
                let decrypted = try CTAP2.LargeBlobs.decrypt(entry: entry, key: key)
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
                _ = try CTAP2.LargeBlobs.decrypt(entry: entry, key: key)
                return true  // Successfully decrypted = same key, remove it
            } catch {
                return false  // Different key, keep it
            }
        }

        // Encrypt and add new entry
        let newEntry = try CTAP2.LargeBlobs.encrypt(data: data, key: key)
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
                _ = try CTAP2.LargeBlobs.decrypt(entry: entry, key: key)
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
}
