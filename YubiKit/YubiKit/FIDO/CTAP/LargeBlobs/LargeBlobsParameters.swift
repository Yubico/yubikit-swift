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

// MARK: - Read Parameters

extension CTAP2.LargeBlobs {
    /// Parameters for reading from the large blob array.
    ///
    /// Used internally by the session to read fragments of the blob array.
    struct ReadParameters: Sendable {
        /// Number of bytes to read.
        let get: UInt

        /// Byte offset to start reading from.
        let offset: UInt

        init(get: UInt, offset: UInt) {
            self.get = get
            self.offset = offset
        }
    }
}

// MARK: - Write Parameters

extension CTAP2.LargeBlobs {
    /// Parameters for writing to the large blob array.
    ///
    /// Used internally by the session to write fragments of the blob array.
    struct WriteParameters: Sendable {
        /// Fragment data to write.
        let set: Data

        /// Byte offset for this fragment.
        let offset: UInt

        /// Total length of data being written (only required on first fragment).
        let length: UInt?

        /// PIN/UV authentication parameter.
        let pinUVAuthParam: Data

        /// PIN/UV protocol version.
        let pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion

        init(
            set: Data,
            offset: UInt,
            length: UInt?,
            pinUVAuthParam: Data,
            pinUVAuthProtocol: CTAP2.ClientPin.ProtocolVersion
        ) {
            self.set = set
            self.offset = offset
            self.length = length
            self.pinUVAuthParam = pinUVAuthParam
            self.pinUVAuthProtocol = pinUVAuthProtocol
        }
    }
}

// MARK: - Response

extension CTAP2.LargeBlobs {
    /// Response from the authenticatorLargeBlobs command.
    struct Response: Sendable {
        /// Configuration data (blob fragment for read operations).
        let config: Data
    }
}

// MARK: - CBOR Encoding

extension CTAP2.LargeBlobs.ReadParameters: CBOR.Encodable {
    func cbor() -> CBOR.Value {
        var map: [CBOR.Value: CBOR.Value] = [:]
        map[.int(0x01)] = get.cbor()
        map[.int(0x03)] = offset.cbor()
        return .map(map)
    }
}

extension CTAP2.LargeBlobs.WriteParameters: CBOR.Encodable {
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

// MARK: - CBOR Decoding

extension CTAP2.LargeBlobs.Response: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue,
            let config = map[.int(0x01)]?.dataValue
        else {
            return nil
        }
        self.config = config
    }
}
