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

/// # RSAKeys
/// Defines RSA public and private key types and DER encoding/decoding utilities for PKCS #1.

import Foundation

public enum RSA {

    /// Supported RSA key sizes (in bits).
    public enum KeySize: Int, Sendable {
        case bits1024 = 1024
        case bits2048 = 2048
        case bits3072 = 3072
        case bits4096 = 4096

        /// Returns the key size in bits.
        public var keySizeInBits: Int {
            return rawValue
        }

        /// Returns the key size in bytes.
        public var keySizeInBytes: Int {
            return rawValue / 8
        }
    }

    /// RSA public key with modulus and exponent.
    /// Uses PKCS #1 DER encoding.
    public struct PublicKey: Sendable, Equatable {
        public let size: KeySize

        public let n: Data  // modulus
        public let e: Data  // public exponent

        /// Initializes an RSA public key.
        /// - Parameters:
        ///   - size: Key size (bits).
        ///   - n: Modulus (big endian, no sign).
        ///   - e: Exponent (big endian).
        ///   - Returns: PublicKey if modulus size matches; otherwise nil.
        public init?(size: KeySize, n: Data, e: Data) {
            guard n.count == size.keySizeInBytes else { return nil }

            self.size = size
            self.n = n
            self.e = e
        }
    }

    /// RSA private key with associated public key and CRT components.
    /// Uses PKCS #1 DER encoding.
    public struct PrivateKey: Sendable, Equatable {
        public let peer: PublicKey

        // Shared
        public var n: Data {
            peer.n
        }

        public var size: KeySize {
            peer.size
        }

        // Private exponent
        public let d: Data

        // CRT-optimized
        public let p: Data    // primeOne
        public let q: Data    // primeTwo
        public let dP: Data   // exponentOne
        public let dQ: Data   // exponentTwo
        public let qInv: Data // coefficient

        /// Initializes an RSA private key.
        /// - Parameters:
        ///   - peer: Corresponding public key.
        ///   - d: Private exponent.
        ///   - p: Prime factor 1.
        ///   - q: Prime factor 2.
        ///   - dP: d mod (p-1).
        ///   - dQ: d mod (q-1).
        ///   - qInv: q⁻¹ mod p.
        public init(peer: PublicKey, d: Data, p: Data, q: Data, dP: Data, dQ: Data, qInv: Data) {
            self.peer = peer
            self.d = d
            self.p = p
            self.q = q
            self.dP = dP
            self.dQ = dQ
            self.qInv = qInv
        }
    }
}

extension RSA.PublicKey {

    /// DER-encoded PKCS #1 public key: `SEQUENCE { n, e }`.
    public var pkcs1: Data {
        var body = Data()

        body.append(PKCS1.Encoder.integer(n))
        body.append(PKCS1.Encoder.integer(e))

        return PKCS1.Encoder.sequence(body)
    }

    /// Initializes public key from DER-encoded PKCS #1 blob.
    /// - Parameters:
    ///   - size: Key size (bits).
    ///   - pkcs1: DER bytes: `SEQUENCE { modulus INTEGER, exponent INTEGER }`.
    ///   - Returns: PublicKey if valid; otherwise nil.
    init?(size: RSA.KeySize, pkcs1: Data) {
        var data = pkcs1

        do {
            try PKCS1.Decoder.sequenceHeader(&data)

            let n = try PKCS1.Decoder.integer(&data)
            let e = try PKCS1.Decoder.integer(&data)

            self.size = size
            self.n = n
            self.e = e

        } catch {
            return nil
        }
    }
}

public extension RSA.PrivateKey {

    /// DER-encoded PKCS #1 private key: `SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }`.
    var pkcs1: Data {
        var body = Data()

        // version = 0
        body.append(PKCS1.Encoder.integer(Data([0x00])))

        body.append(PKCS1.Encoder.integer(n))
        body.append(PKCS1.Encoder.integer(peer.e))
        body.append(PKCS1.Encoder.integer(d))
        body.append(PKCS1.Encoder.integer(p))
        body.append(PKCS1.Encoder.integer(q))
        body.append(PKCS1.Encoder.integer(dP))
        body.append(PKCS1.Encoder.integer(dQ))
        body.append(PKCS1.Encoder.integer(qInv))

        return PKCS1.Encoder.sequence(body)
    }

    /// Initializes private key from DER-encoded PKCS #1 blob.
    /// - Parameters:
    ///   - size: Key size (bits).
    ///   - pkcs1: DER bytes for the full private key.
    ///   - Returns: PrivateKey if valid; otherwise nil.
    init?(size: RSA.KeySize, pkcs1: Data) {
        var data = pkcs1

        do {
            try PKCS1.Decoder.sequenceHeader(&data)

            let version = try PKCS1.Decoder.integer(&data)
            // We only support two‑prime RSA (version = 0)
            guard version.count == 1, version.first == 0 else { throw PKCS1.Error(message: "Unsupported version") }

            let n = try PKCS1.Decoder.integer(&data)
            let e       = try PKCS1.Decoder.integer(&data)
            let d       = try PKCS1.Decoder.integer(&data)
            let p       = try PKCS1.Decoder.integer(&data)
            let q       = try PKCS1.Decoder.integer(&data)
            let dP      = try PKCS1.Decoder.integer(&data)
            let dQ      = try PKCS1.Decoder.integer(&data)
            let qInv    = try PKCS1.Decoder.integer(&data)

            guard let peer: RSA.PublicKey = .init(size: size, n: n, e: e) else {
                throw PKCS1.Error(message: "Failed to create public peer key")
            }

            self.peer = peer
            self.d = d
            self.p = p
            self.q = q
            self.dP = dP
            self.dQ = dQ
            self.qInv = qInv

        } catch {
            return nil
        }
    }
}

// MARK: - PKCS #1 DER Encoding/Decoding Utilities
private enum PKCS1 {
    struct Error: Swift.Error {
        let message: String
    }

    enum Encoder {

        /// DER-encodes a SEQUENCE containing `body`.
        ///
        /// - Returns: `0x30 || length || body`
        static func sequence(_ body: Data) -> Data {
            if body.isEmpty { return Data() }

            var out = Data([0x30])          // SEQUENCE tag
            out.append(encodeLength(body.count))
            out.append(body)
            return out
        }

        /// DER-encodes an INTEGER.
        ///
        /// - Parameter value: Big-endian magnitude bytes (positive integer).
        /// - Returns: `0x02 || length || value`
        static func integer(_ value: Data) -> Data {
            if value.isEmpty { return Data() }

            var content = value

            // Strip redundant leading 0x00
            while content.count > 1 && content.bytes.first == 0x00 {
                content.removeFirst()
            }

            // Add sign byte if MSB is 1 (ensure positive)
            if let firstByte = content.bytes.first, firstByte & 0x80 != 0 {
                content = [0x00] + content
            }

            return Data([0x02]) + encodeLength(content.count) + content
        }

        // MARK: - Helpers

        /// DER length encoder (definite form, up to 4 bytes of length).
        private static func encodeLength(_ len: Int) -> Data {
            guard len >= 0 else { return Data()}

            if len < 0x80 { // Short form
                return Data([UInt8(len)])
            } else { // Long form
                var tmp = withUnsafeBytes(of: UInt32(len).bigEndian, Array.init)
                // strip leading zeros
                while tmp.first == 0 { tmp.removeFirst() }
                var out = Data([0x80 | UInt8(tmp.count)])
                out.append(contentsOf: tmp)
                return out
            }
        }
    }

    enum Decoder {

        /// Consumes the DER SEQUENCE tag + length and sanity-checks that the
        /// remaining buffer actually contains the declared number of bytes.
        ///
        /// On return `data` starts at the first byte **inside** the SEQUENCE.
        ///
        /// - Parameter data: Buffer to parse (advanced past the SEQUENCE header).
        /// - Throws: `PKCS1.Error` if the tag, length, or remaining bytes are invalid.
        static func sequenceHeader(_ data: inout Data) throws {
            // Tag
            guard data.first == 0x30 else { throw PKCS1.Error(message: "Expected SEQUENCE") }
            data.removeFirst()

            // Length
            let length = try decodeLength(&data)

            // Sanity-check: make sure we actually have that many bytes left
            guard data.count >= length else { throw PKCS1.Error(message: "Truncated SEQUENCE") }
            // Nothing else to do: the caller will now read `length` bytes worth of fields.
        }

        /// Reads an ASN.1 DER INTEGER and returns its raw bytes.
        ///
        /// - Parameter data: The input buffer (advanced past the integer on return).
        /// - Returns: The INTEGER content bytes.
        /// - Throws: `PKCS1.Error` if the tag/length/contents are malformed.
        static func integer(_ data: inout Data) throws -> Data {
            // Tag
            guard data.first == 0x02 else { throw PKCS1.Error(message: "Expected INTEGER") }
            data.removeFirst()

            // Length
            let length = try decodeLength(&data)

            // Value
            guard data.count >= length else { throw PKCS1.Error(message: "Truncated INTEGER") }
            let value = data.prefix(length)
            data.removeFirst(length)

            // Strip any leading padding 0x00 bytes (non‑canonical positive INTEGER encoding)
            var trimmed = Data(value)
            while trimmed.count > 1 && trimmed.first == 0x00 {
                trimmed.removeFirst()
            }

            return trimmed
        }

        // MARK: - Helpers

        /// DER length decoder (definite form only).
        private static func decodeLength(_ data: inout Data) throws -> Int {
            guard let first = data.first else { throw PKCS1.Error(message: "Missing length") }
            data.removeFirst()

            if first & 0x80 == 0 { // Short form (≤ 127)
                return Int(first)
            } else { // Long form
                let octets = Int(first & 0x7F)
                guard octets > 0, octets <= 4, data.count >= octets else {
                    throw PKCS1.Error(message: "Invalid length")
                }
                var length: Int = 0
                for _ in 0..<octets {
                    length = (length << 8) | Int(data.removeFirst())
                }
                return length
            }
        }
    }
}
