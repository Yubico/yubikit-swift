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

extension Crypto.X509 {
    static func extractPostQuantumPublicKey(fromDER der: Data) -> PublicKey? {
        var certificate = DERReader(der)
        guard let outer = certificate.read(tag: 0x30), certificate.isAtEnd else { return nil }
        var outerReader = DERReader(outer)
        guard let tbs = outerReader.read(tag: 0x30) else { return nil }
        var tbsReader = DERReader(tbs)

        if tbsReader.peekTag == 0xa0 {
            guard tbsReader.read(tag: 0xa0) != nil else { return nil }
        }
        // serialNumber, signature, issuer, validity, subject
        for tag: UInt8 in [0x02, 0x30, 0x30, 0x30, 0x30] {
            guard tbsReader.read(tag: tag) != nil else { return nil }
        }
        guard let spki = tbsReader.read(tag: 0x30) else { return nil }
        var spkiReader = DERReader(spki)
        guard let algorithm = spkiReader.read(tag: 0x30),
            let bitString = spkiReader.read(tag: 0x03),
            spkiReader.isAtEnd,
            bitString.first == 0
        else { return nil }
        var algorithmReader = DERReader(algorithm)
        guard let oid = algorithmReader.read(tag: 0x06), algorithmReader.isAtEnd else { return nil }
        let keyData = Data(bitString.dropFirst())

        for parameterSet in MLDSA.ParameterSet.allCases where oid == parameterSet.oid {
            guard let key = MLDSA.PublicKey(keyData: keyData, parameterSet: parameterSet) else { return nil }
            return .mlDSA(key)
        }
        for parameterSet in MLKEM.ParameterSet.allCases where oid == parameterSet.oid {
            guard let key = MLKEM.PublicKey(keyData: keyData, parameterSet: parameterSet) else { return nil }
            return .mlKEM(key)
        }
        return nil
    }
}

private struct DERReader {
    private let bytes: Data
    private var offset = 0

    init(_ bytes: Data) { self.bytes = Data(Array(bytes)) }

    var isAtEnd: Bool { offset == bytes.count }
    var peekTag: UInt8? { offset < bytes.count ? bytes[offset] : nil }

    mutating func read(tag: UInt8) -> Data? {
        guard offset + 2 <= bytes.count, bytes[offset] == tag else { return nil }
        offset += 1
        let firstLength = bytes[offset]
        offset += 1
        let length: Int
        if firstLength < 0x80 {
            length = Int(firstLength)
        } else {
            let count = Int(firstLength & 0x7f)
            guard count > 0, count <= 4, offset + count <= bytes.count else { return nil }
            guard bytes[offset] != 0 else { return nil }
            var decoded = 0
            for _ in 0..<count {
                decoded = (decoded << 8) | Int(bytes[offset])
                offset += 1
            }
            guard decoded >= 0x80 else { return nil }
            length = decoded
        }
        guard length <= bytes.count - offset else { return nil }
        let result = bytes.subdata(in: offset..<(offset + length))
        offset += length
        return result
    }
}
