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

// MARK: - Blob Array

extension CTAP2.LargeBlobs {
    // CBOR-encoded list of encrypted blob entries with 16-byte SHA-256 checksum.
    struct BlobArray: Sendable, Equatable {
        var entries: [Entry]

        init() {
            self.entries = []
        }
    }
}

// MARK: - Blob Entry

extension CTAP2.LargeBlobs.BlobArray {
    struct Entry: Sendable, Equatable {
        let ciphertext: Data
        let nonce: Data
        let origSize: Int
    }
}

// MARK: - CBOR Encoding

extension CTAP2.LargeBlobs.BlobArray: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        .array(entries.map { $0.cbor() })
    }
}

extension CTAP2.LargeBlobs.BlobArray.Entry: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[.int(0x01)] = ciphertext.cbor()
        map[.int(0x02)] = nonce.cbor()
        map[.int(0x03)] = origSize.cbor()
        return .map(map)
    }
}

// MARK: - CBOR Decoding

extension CTAP2.LargeBlobs.BlobArray: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let array = cbor.arrayValue else {
            return nil
        }
        var entries: [Entry] = []
        for element in array {
            guard let entry = Entry(cbor: element) else {
                return nil
            }
            entries.append(entry)
        }
        self.entries = entries
    }
}

extension CTAP2.LargeBlobs.BlobArray.Entry: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let ciphertext = map[.int(0x01)]?.dataValue,
            let nonce = map[.int(0x02)]?.dataValue,
            let origSize = map[.int(0x03)]?.intValue
        else {
            return nil
        }
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.origSize = origSize
    }
}
