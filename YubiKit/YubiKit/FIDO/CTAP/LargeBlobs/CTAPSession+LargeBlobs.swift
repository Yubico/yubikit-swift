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

    // maxFragmentLength = maxMsgSize - 64, as per spec.
    private static let maxFragmentLengthOverhead = 64
    // Length of the checksum appended to the serialized blob array.
    private static let checksumLength = 16

    // MARK: - Support Check

    /// Checks if the authenticator supports large blobs.
    ///
    /// - Returns: `true` if the authenticator supports the `largeBlobs` option.
    public func supportsLargeBlobs() async throws(CTAP2.SessionError) -> Bool {
        let info = try await getInfo()
        return info.options.largeBlobs == true
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
        let entries = try await readBlobArray()

        for entry in entries {
            if let decrypted = try? entry.decrypt(key: key) {
                return decrypted
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
        var entries = try await readBlobArray()

        // Remove existing entries for this key
        entries.removeAll { entry in
            (try? entry.decrypt(key: key)) != nil
        }

        // Encrypt and add new entry
        let newEntry = try CTAP2.LargeBlobs.Entry(encrypting: data, key: key)
        entries.append(newEntry)

        try await writeBlobArray(entries, pinToken: pinToken)
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
        var entries = try await readBlobArray()
        let originalCount = entries.count

        entries.removeAll { entry in
            (try? entry.decrypt(key: key)) != nil
        }

        if entries.count != originalCount {
            try await writeBlobArray(entries, pinToken: pinToken)
        }
    }

    // MARK: - Private Array Operations

    // Reads the entire large blob array with checksum validation.
    private func readBlobArray() async throws(CTAP2.SessionError) -> [CTAP2.LargeBlobs.Entry] {
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
        guard checksum == self.checksum(content) else {
            throw .ctapError(.integrityFailure, source: .here())
        }

        // Parse CBOR array
        guard !content.isEmpty else {
            return []
        }

        guard let cbor: CBOR.Value = try? content.decode(),
            let array = cbor.arrayValue
        else {
            throw .responseParseError("Failed to parse large blob array", source: .here())
        }

        return array.compactMap { CTAP2.LargeBlobs.Entry(cbor: $0) }
    }

    // Writes the entire large blob array with automatic fragmentation.
    private func writeBlobArray(
        _ entries: [CTAP2.LargeBlobs.Entry],
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
        let info = try await getInfo()
        let maxFragment = Int(info.maxMsgSize) - Self.maxFragmentLengthOverhead

        // Encode array and append checksum
        let encoded = CBOR.Value.array(entries.map { $0.cbor() }).encode()
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
        return try await stream.value.config
    }

    // Writes a fragment to the large blob array.
    private func writeLargeBlobFragment(
        set: Data,
        offset: UInt,
        length: UInt?,
        pinToken: CTAP2.ClientPin.Token
    ) async throws(CTAP2.SessionError) {
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

    // MARK: - Helpers

    // Computes the SHA-256 checksum truncated to 16 bytes.
    private func checksum(_ data: Data) -> Data {
        data.sha256().prefix(Self.checksumLength)
    }

    // Computes the PIN/UV auth message for write operations.
    private func writeAuthMessage(fragment: Data, offset: UInt) -> Data {
        var message = Data(repeating: 0xFF, count: 32)
        message.append(contentsOf: [0x0C, 0x00])
        var offsetLE = UInt32(offset).littleEndian
        message.append(Data(bytes: &offsetLE, count: 4))
        message.append(fragment.sha256())
        return message
    }

    // MARK: - CTAP Parameters

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
