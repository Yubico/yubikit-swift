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

// Warning: test scaffolding only. An unreviewed implementation of a draft spec
// (draft-bradleylundberg-cfrg-arkg), here so the scenarios can verify an authenticator's ARKG
// output instead of trusting it. Not constant-time, does not check that points are on the curve,
// no known-answer coverage. Do not move it into the SDK.

// MARK: - Error types

enum ARKGError: Error, LocalizedError {
    case unexpectedAlgorithm(Int)
    case notAnARKGSeed
    case contextTooLong
    case expandMessageXmdInputTooLarge

    var errorDescription: String? {
        switch self {
        case .unexpectedAlgorithm(let alg): return "Expected an ESP256-split-ARKG key, got algorithm \(alg)"
        case .notAnARKGSeed: return "Generated public key is not an ARKG-P256 seed"
        case .contextTooLong: return "Context must be at most 64 bytes"
        case .expandMessageXmdInputTooLarge: return "expand_message_xmd: input size out of range"
        }
    }
}

// MARK: - ARKG

enum ARKG {
    // RFC 9380 domain separation
    private static let dstExt = Data("ARKG-P256".utf8)
    private static let kemDstExt = Data("ARKG-ECDH.ARKG-P256".utf8)
    private static let hashToFieldL = 48  // bytes of XMD output per field element

    // MARK: - Public API

    static func derivePublicKey(
        pkKem: Data,
        pkBl: Data,
        ikm: Data,
        context: Data
    ) throws -> (publicKey: Data, arkgKeyHandle: Data) {
        guard context.count <= 64 else { throw ARKGError.contextTooLong }

        let ctxPrime = Data([UInt8(context.count)]) + context
        let ctxBl = Data("ARKG-Derive-Key-BL.".utf8) + ctxPrime
        let ctxKem = Data("ARKG-Derive-Key-KEM.".utf8) + ctxPrime

        let (ikmTau, c) = try kemEncaps(pkKem: pkKem, ikm: ikm, ctxKem: ctxKem)
        let tau = try blPrf(ikmTau: ikmTau, ctxBl: ctxBl)
        let tauG = try p256ScalarMulG(scalar: tau)
        let pkPrime = try p256Add(pkBl, tauG)

        return (pkPrime, c)
    }

    // The seed's blinding and key-encapsulation keys as uncompressed points, or nil if `cose` is
    // not an ARKG-P256 seed. Its -1 and -2 members are themselves EC2 keys, so it is not a plain
    // COSE key.
    static func seedPoints(fromCOSE cose: Data) -> (pkBl: Data, pkKem: Data)? {
        let arkgP256Algorithm = -65700
        guard
            let seed = decodeCBOR(cose)?.mapValue,
            seed[3]?.intValue == arkgP256Algorithm
        else { return nil }

        func point(_ label: Int) -> Data? {
            guard
                let ec2 = seed[label]?.mapValue,
                let x = ec2[-2]?.bytesValue, x.count == 32,
                let y = ec2[-3]?.bytesValue, y.count == 32
            else { return nil }
            return Data([0x04]) + x + y
        }
        guard let pkBl = point(-1), let pkKem = point(-2) else { return nil }
        return (pkBl, pkKem)
    }

    // COSE_Sign_Args for GetAssertion: { 3: -65539, -2: context, -1: arkgKeyHandle }.
    static func buildAdditionalArgs(context: Data, arkgKeyHandle: Data) -> Data {
        // Written out directly because YubiKit's CBOR encoder is internal to the SDK.
        // Major type 1 encodes -1-n; major type 2 is a byte string.
        func header(major: UInt8, _ n: Int) -> Data {
            if n < 24 { return Data([major | UInt8(n)]) }
            if n < 0x1_00 { return Data([major | 24, UInt8(n)]) }
            if n < 0x1_0000 { return Data([major | 25, UInt8(n >> 8), UInt8(n & 0xFF)]) }
            return Data([major | 26, UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)])
        }
        func int(_ value: Int) -> Data {
            value < 0 ? header(major: 0x20, -1 - value) : header(major: 0x00, value)
        }
        func bytes(_ data: Data) -> Data { header(major: 0x40, data.count) + data }

        return Data([0xA3])  // map, 3 pairs — CTAP2 canonical order: 3, -1, -2
            + int(3) + int(-65539)
            + int(-1) + bytes(arkgKeyHandle)
            + int(-2) + bytes(context)
    }

    // Pass the message, not its digest: CryptoKit applies SHA-256 internally, reproducing the
    // digest the app sent as `tbs`.
    static func verifySignature(publicKey: Data, message: Data, derSignature: Data) -> Bool {
        guard let pubKey = try? P256.Signing.PublicKey(x963Representation: publicKey),
            let sig = try? P256.Signing.ECDSASignature(derRepresentation: derSignature)
        else { return false }
        return pubKey.isValidSignature(sig, for: message)
    }

    // MARK: - KEM (ARKG-KEM-HMAC)

    private static func kemEncaps(
        pkKem: Data,
        ikm: Data,
        ctxKem: Data
    ) throws -> (ikmTau: Data, c: Data) {
        // The spec's ctx_sub is not derived here: the ECDH sub-KEM ignores its context, so it
        // would never reach a hash.
        let (kPrime, cPrime) = try subKemEncaps(pkKem: pkKem, ikm: ikm)

        let mk = hkdfSha256(
            ikm: kPrime,
            info: Data("ARKG-KEM-HMAC-mac.".utf8) + kemDstExt + ctxKem,
            length: 32
        )
        let fullMac = hmacSha256(key: mk, message: cPrime)
        let tau = Data(fullMac.prefix(16))

        let k = hkdfSha256(
            ikm: kPrime,
            info: Data("ARKG-KEM-HMAC-shared.".utf8) + kemDstExt + ctxKem,
            length: kPrime.count
        )
        return (k, tau + cPrime)  // keyHandle = truncatedMAC || ephemeralPubKey
    }

    private static func subKemEncaps(
        pkKem: Data,
        ikm: Data
    ) throws -> (k: Data, cPrime: Data) {
        let (pkPrime, skPrime) = try subKemDeriveKeyPair(ikm: ikm)
        let k = try p256ECDH(privateScalar: skPrime, publicPoint: pkKem)
        return (k, pkPrime)
    }

    private static func subKemDeriveKeyPair(ikm: Data) throws -> (pk: Data, sk: Data) {
        let dst = Data("ARKG-KEM-ECDH-KG.".utf8) + kemDstExt
        let sk = try hashToField(msg: ikm, count: 1, dst: dst)[0]
        let pk = try p256ScalarMulG(scalar: sk)
        return (pk, sk)
    }

    // MARK: - Blinding PRF

    private static func blPrf(ikmTau: Data, ctxBl: Data) throws -> Data {
        let dst = Data("ARKG-BL-EC.".utf8) + dstExt + ctxBl
        return try hashToField(msg: ikmTau, count: 1, dst: dst)[0]
    }

    // MARK: - Hash to field (RFC 9380)

    // `count` 32-byte scalars, each an element of Z/nZ.
    private static func hashToField(msg: Data, count: Int, dst: Data) throws -> [Data] {
        let expanded = try expandMessageXmd(msg: msg, lenInBytes: count * hashToFieldL, dst: dst)
        return (0..<count).map { i in
            let slice = expanded[(i * hashToFieldL)..<((i + 1) * hashToFieldL)]
            return p256ModN48(Data(slice))
        }
    }

    // RFC 9380 §5.4.1 expand_message_xmd with SHA-256.
    private static func expandMessageXmd(msg: Data, lenInBytes: Int, dst: Data) throws -> Data {
        let bInBytes = 32  // SHA-256 output
        let sInBytes = 64  // SHA-256 block size
        let ell = (lenInBytes + bInBytes - 1) / bInBytes
        guard ell <= 255, lenInBytes <= 65535, dst.count <= 255 else {
            throw ARKGError.expandMessageXmdInputTooLarge
        }

        let dstPrime = dst + Data([UInt8(dst.count)])
        let zPad = Data(repeating: 0, count: sInBytes)
        let lIBStr = Data([UInt8((lenInBytes >> 8) & 0xFF), UInt8(lenInBytes & 0xFF)])
        let msgPrime = zPad + msg + lIBStr + Data([0x00]) + dstPrime

        let b0 = Data(SHA256.hash(data: msgPrime))
        var bXor = b0  // i=1 hashes b0; later rounds hash b0 XOR b_(i-1)
        var uniformBytes = Data()

        for i in 1...ell {
            let input = bXor + Data([UInt8(i)]) + dstPrime
            let bi = Data(SHA256.hash(data: input))
            uniformBytes += bi
            bXor = xorBytes(b0, bi)
        }

        return Data(uniformBytes.prefix(lenInBytes))
    }

    // MARK: - Symmetric crypto

    // Null salt, i.e. 32 zero bytes per RFC 5869 §2.2.
    private static func hkdfSha256(ikm: Data, info: Data, length: Int) -> Data {
        let salt = Data(repeating: 0, count: 32)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: length
        )
        return key.withUnsafeBytes { Data($0) }
    }

    private static func hmacSha256(key: Data, message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    // MARK: - EC primitives (backed by CryptoKit + P256Arithmetic)

    private static func p256ScalarMulG(scalar: Data) throws -> Data {
        let priv = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        return priv.publicKey.x963Representation
    }

    // x-coordinate of privateScalar × publicPoint, 32 bytes big-endian.
    private static func p256ECDH(privateScalar: Data, publicPoint: Data) throws -> Data {
        let priv = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateScalar)
        let pub = try P256.KeyAgreement.PublicKey(x963Representation: publicPoint)
        return try priv.sharedSecretFromKeyAgreement(with: pub).withUnsafeBytes { Data($0) }
    }

    // MARK: - CBOR (only enough to read a COSE key)

    // Definite-length major types 0-5 only: tags and floats never appear in a COSE key, and an
    // indefinite length would mean non-canonical CBOR, which is itself a failure. Non-integer map
    // keys are parsed to advance the cursor, then discarded.
    private indirect enum CBORValue {
        case int(Int)
        case bytes(Data)
        case text(String)
        case array([CBORValue])
        case map([Int: CBORValue])

        var intValue: Int? {
            if case .int(let value) = self { return value }
            return nil
        }

        var bytesValue: Data? {
            if case .bytes(let data) = self { return data }
            return nil
        }

        var mapValue: [Int: CBORValue]? {
            if case .map(let map) = self { return map }
            return nil
        }
    }

    // One item, required to consume `data` exactly.
    private static func decodeCBOR(_ data: Data) -> CBORValue? {
        var cursor = data.startIndex
        guard let value = decodeCBORItem(data, &cursor), cursor == data.endIndex else { return nil }
        return value
    }

    private static func decodeCBORItem(_ data: Data, _ cursor: inout Int) -> CBORValue? {
        guard cursor < data.endIndex else { return nil }
        let initial = data[cursor]
        cursor += 1
        guard let argument = decodeCBORArgument(data, &cursor, info: initial & 0x1F) else { return nil }

        switch initial >> 5 {
        case 0:
            return Int(exactly: argument).map { .int($0) }
        case 1:
            return Int(exactly: argument).map { .int(-1 - $0) }
        case 2:
            guard let end = cborOffset(data, cursor, by: argument) else { return nil }
            let bytes = Data(data[cursor..<end])
            cursor = end
            return .bytes(bytes)
        case 3:
            guard let end = cborOffset(data, cursor, by: argument),
                let text = String(data: Data(data[cursor..<end]), encoding: .utf8)
            else { return nil }
            cursor = end
            return .text(text)
        case 4:
            // Each element needs at least one byte, so the remaining length bounds the count.
            guard argument <= UInt64(data.endIndex - cursor) else { return nil }
            var items: [CBORValue] = []
            for _ in 0..<argument {
                guard let item = decodeCBORItem(data, &cursor) else { return nil }
                items.append(item)
            }
            return .array(items)
        case 5:
            guard argument <= UInt64(data.endIndex - cursor) else { return nil }
            var map: [Int: CBORValue] = [:]
            for _ in 0..<argument {
                guard let key = decodeCBORItem(data, &cursor), let value = decodeCBORItem(data, &cursor)
                else { return nil }
                if let key = key.intValue { map[key] = value }
            }
            return .map(map)
        default:
            return nil
        }
    }

    // Inlined in the initial byte, or the 1/2/4/8 bytes that follow it.
    private static func decodeCBORArgument(_ data: Data, _ cursor: inout Int, info: UInt8) -> UInt64? {
        switch info {
        case 0...23: return UInt64(info)
        case 24: return readBigEndian(data, &cursor, count: 1)
        case 25: return readBigEndian(data, &cursor, count: 2)
        case 26: return readBigEndian(data, &cursor, count: 4)
        case 27: return readBigEndian(data, &cursor, count: 8)
        default: return nil
        }
    }

    private static func readBigEndian(_ data: Data, _ cursor: inout Int, count: Int) -> UInt64? {
        guard let end = cborOffset(data, cursor, by: UInt64(count)) else { return nil }
        var value: UInt64 = 0
        for byte in data[cursor..<end] { value = value << 8 | UInt64(byte) }
        cursor = end
        return value
    }

    private static func cborOffset(_ data: Data, _ cursor: Int, by count: UInt64) -> Int? {
        guard count <= UInt64(data.endIndex - cursor) else { return nil }
        return cursor + Int(count)
    }
}

// MARK: - Helpers

private func xorBytes(_ a: Data, _ b: Data) -> Data {
    precondition(a.count == b.count)
    return Data(zip(a, b).map { $0 ^ $1 })
}
