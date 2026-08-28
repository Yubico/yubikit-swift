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

// Warning: test scaffolding only — see ARKG.swift. Everything here branches on its inputs, so it
// leaks through timing. It exists because CryptoKit has no EC point addition, and is only ever
// fed public ARKG values.

// MARK: - 256-bit Integer (4 × UInt64, little-endian limbs)

private struct UInt256: Equatable {
    var v0, v1, v2, v3: UInt64

    // init(bigEndian:) suppresses the memberwise init.
    init(v0: UInt64, v1: UInt64, v2: UInt64, v3: UInt64) {
        self.v0 = v0
        self.v1 = v1
        self.v2 = v2
        self.v3 = v3
    }

    static let zero = UInt256(v0: 0, v1: 0, v2: 0, v3: 0)
    static let one = UInt256(v0: 1, v1: 0, v2: 0, v3: 0)

    // p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    static let p256p = UInt256(
        v0: 0xFFFF_FFFF_FFFF_FFFF,
        v1: 0x0000_0000_FFFF_FFFF,
        v2: 0x0000_0000_0000_0000,
        v3: 0xFFFF_FFFF_0000_0001
    )

    static let p256n = UInt256(
        v0: 0xF3B9_CAC2_FC63_2551,
        v1: 0xBCE6_FAAD_A717_9E84,
        v2: 0xFFFF_FFFF_FFFF_FFFF,
        v3: 0xFFFF_FFFF_0000_0000
    )

    init(bigEndian data: Data) {
        precondition(data.count == 32)
        let bytes = [UInt8](data)
        func load(_ i: Int) -> UInt64 {
            let off = i * 8
            return UInt64(bytes[off]) << 56 | UInt64(bytes[off + 1]) << 48
                | UInt64(bytes[off + 2]) << 40 | UInt64(bytes[off + 3]) << 32
                | UInt64(bytes[off + 4]) << 24 | UInt64(bytes[off + 5]) << 16
                | UInt64(bytes[off + 6]) << 8 | UInt64(bytes[off + 7])
        }
        v3 = load(0)
        v2 = load(1)
        v1 = load(2)
        v0 = load(3)
    }

    var bigEndian: Data {
        func store(_ x: UInt64) -> [UInt8] {
            let b7 = UInt8((x >> 56) & 0xFF)
            let b6 = UInt8((x >> 48) & 0xFF)
            let b5 = UInt8((x >> 40) & 0xFF)
            let b4 = UInt8((x >> 32) & 0xFF)
            let b3 = UInt8((x >> 24) & 0xFF)
            let b2 = UInt8((x >> 16) & 0xFF)
            let b1 = UInt8((x >> 8) & 0xFF)
            let b0 = UInt8(x & 0xFF)
            return [b7, b6, b5, b4, b3, b2, b1, b0]
        }
        return Data(store(v3) + store(v2) + store(v1) + store(v0))
    }

    func isLessThan(_ other: UInt256) -> Bool {
        if v3 != other.v3 { return v3 < other.v3 }
        if v2 != other.v2 { return v2 < other.v2 }
        if v1 != other.v1 { return v1 < other.v1 }
        return v0 < other.v0
    }

    var isZero: Bool { v0 == 0 && v1 == 0 && v2 == 0 && v3 == 0 }
}

// MARK: - Public helpers for ARKG

// 48 big-endian bytes reduced mod n, returned as 32 big-endian bytes in [0, n-1].
func p256ModN48(_ bytes48: Data) -> Data {
    precondition(bytes48.count == 48)
    let padded = Data(repeating: 0, count: 16) + bytes48  // 512 bits
    var limbs = [UInt64](repeating: 0, count: 8)
    for i in 0..<8 {
        let off = (7 - i) * 8
        limbs[i] =
            UInt64(padded[off]) << 56 | UInt64(padded[off + 1]) << 48
            | UInt64(padded[off + 2]) << 40 | UInt64(padded[off + 3]) << 32
            | UInt64(padded[off + 4]) << 24 | UInt64(padded[off + 5]) << 16
            | UInt64(padded[off + 6]) << 8 | UInt64(padded[off + 7])
    }
    return reduce512(limbs, mod: .p256n).bigEndian
}

// MARK: - Modular arithmetic mod p (P-256 field prime)

// (a - b) mod m, inputs < m
private func submod(_ a: UInt256, _ b: UInt256, mod m: UInt256) -> UInt256 {
    if b.isLessThan(a) || a == b {
        return sub256NoUnderflow(a, b)
    }
    // a + m can wrap past 2^256; the subtraction cancels it.
    return sub256NoUnderflow(add256(a, m), b)
}

private func mulmod(_ a: UInt256, _ b: UInt256, mod m: UInt256) -> UInt256 {
    reduce512(mul256(a, b), mod: m)
}

// a^exp mod m (binary exponentiation)
private func powmod(_ base: UInt256, exp: UInt256, mod m: UInt256) -> UInt256 {
    var result = UInt256.one
    var b = base
    var e = exp
    while !e.isZero {
        if e.v0 & 1 == 1 { result = mulmod(result, b, mod: m) }
        b = mulmod(b, b, mod: m)
        e = shr1(e)
    }
    return result
}

// Fermat's little theorem: a^(m-2) mod m, m prime
private func modinv(_ a: UInt256, mod m: UInt256) -> UInt256 {
    let exp = sub256NoUnderflow(m, UInt256(v0: 2, v1: 0, v2: 0, v3: 0))
    return powmod(a, exp: exp, mod: m)
}

// MARK: - EC Point Addition on P-256 (affine coordinates)

private enum P256ArithmeticError: Error {
    case invalidPoint
    case pointAtInfinity
}

// Add two P-256 points in uncompressed form (04 || x32 || y32).
// Requires P1 ≠ P2 and P1 ≠ -P2 (no infinity handling needed for ARKG).
func p256Add(_ p1: Data, _ p2: Data) throws -> Data {
    guard p1.count == 65, p2.count == 65, p1.first == 0x04, p2.first == 0x04 else {
        throw P256ArithmeticError.invalidPoint
    }
    let p = UInt256.p256p
    let x1 = UInt256(bigEndian: p1[1...32])
    let y1 = UInt256(bigEndian: p1[33...64])
    let x2 = UInt256(bigEndian: p2[1...32])
    let y2 = UInt256(bigEndian: p2[33...64])

    // λ = (y2 - y1) / (x2 - x1) mod p
    let dy = submod(y2, y1, mod: p)
    let dx = submod(x2, x1, mod: p)
    guard !dx.isZero else { throw P256ArithmeticError.pointAtInfinity }
    let lambda = mulmod(dy, modinv(dx, mod: p), mod: p)

    // x3 = λ² - x1 - x2 mod p
    let lambda2 = mulmod(lambda, lambda, mod: p)
    let x3 = submod(submod(lambda2, x1, mod: p), x2, mod: p)

    // y3 = λ(x1 - x3) - y1 mod p
    let y3 = submod(mulmod(lambda, submod(x1, x3, mod: p), mod: p), y1, mod: p)

    return Data([0x04]) + x3.bigEndian + y3.bigEndian
}

// MARK: - 256-bit arithmetic primitives

// Wraps modulo 2^256.
private func add256(_ a: UInt256, _ b: UInt256) -> UInt256 {
    let (v0, c0) = a.v0.addingReportingOverflow(b.v0)
    let (v1a, c1a) = a.v1.addingReportingOverflow(b.v1)
    let (v1, c1b) = v1a.addingReportingOverflow(c0 ? 1 : 0)
    let (v2a, c2a) = a.v2.addingReportingOverflow(b.v2)
    let (v2, c2b) = v2a.addingReportingOverflow(c1a || c1b ? 1 : 0)
    let v3 = a.v3 &+ b.v3 &+ (c2a || c2b ? 1 : 0)
    return UInt256(v0: v0, v1: v1, v2: v2, v3: v3)
}

// Caller ensures a >= b.
private func sub256NoUnderflow(_ a: UInt256, _ b: UInt256) -> UInt256 {
    let (v0, b0) = a.v0.subtractingReportingOverflow(b.v0)
    let (v1a, b1a) = a.v1.subtractingReportingOverflow(b.v1)
    let (v1, b1b) = v1a.subtractingReportingOverflow(b0 ? 1 : 0)
    let borrow1 = b1a || b1b
    let (v2a, b2a) = a.v2.subtractingReportingOverflow(b.v2)
    let (v2, b2b) = v2a.subtractingReportingOverflow(borrow1 ? 1 : 0)
    let borrow2 = b2a || b2b
    let (v3a, _) = a.v3.subtractingReportingOverflow(b.v3)
    let (v3, _) = v3a.subtractingReportingOverflow(borrow2 ? 1 : 0)
    return UInt256(v0: v0, v1: v1, v2: v2, v3: v3)
}

private func shr1(_ a: UInt256) -> UInt256 {
    UInt256(
        v0: (a.v0 >> 1) | (a.v1 << 63),
        v1: (a.v1 >> 1) | (a.v2 << 63),
        v2: (a.v2 >> 1) | (a.v3 << 63),
        v3: a.v3 >> 1
    )
}

// 256×256 → 512-bit schoolbook multiply, returning 8 LE limbs.
private func mul256(_ a: UInt256, _ b: UInt256) -> [UInt64] {
    let aLimbs: [UInt64] = [a.v0, a.v1, a.v2, a.v3]
    let bLimbs: [UInt64] = [b.v0, b.v1, b.v2, b.v3]
    var result = [UInt64](repeating: 0, count: 8)
    for i in 0..<4 {
        var carry: UInt64 = 0
        for j in 0..<4 {
            let (hi, lo) = aLimbs[i].multipliedFullWidth(by: bLimbs[j])
            let (r, c1) = result[i + j].addingReportingOverflow(lo)
            let (r2, c2) = r.addingReportingOverflow(carry)
            result[i + j] = r2
            carry = hi &+ (c1 ? 1 : 0) &+ (c2 ? 1 : 0)
        }
        result[i + 4] = carry
    }
    return result
}

// Binary long division. Requires m > 2^255, true for both p and n.
private func reduce512(_ limbs: [UInt64], mod m: UInt256) -> UInt256 {
    let negM = sub256NoUnderflow(.zero, m)  // 2^256 - m
    var r = UInt256.zero
    for limb in stride(from: 7, through: 0, by: -1) {
        for bit in stride(from: 63, through: 0, by: -1) {
            // r := 2*r, keeping the bit shifted out as the 2^256 overflow.
            let overflow = (r.v3 >> 63) == 1
            r = UInt256(
                v0: r.v0 << 1,
                v1: (r.v1 << 1) | (r.v0 >> 63),
                v2: (r.v2 << 1) | (r.v1 >> 63),
                v3: (r.v3 << 1) | (r.v2 >> 63)
            )
            // Safe: r's LSB is 0 after the shift.
            let inputBit = (limbs[limb] >> bit) & 1
            if inputBit == 1 { r = add256(r, .one) }

            // Previous r < m and m > 2^255, so the value is < 2m and one -m suffices.
            if overflow { r = add256(r, negM) }
            if !r.isLessThan(m) { r = sub256NoUnderflow(r, m) }
        }
    }
    return r
}

// MARK: - Data subscript helpers

extension Data {
    // Offsets are relative to startIndex, so slices of a larger buffer work.
    fileprivate subscript(range: ClosedRange<Int>) -> Data {
        let lower = startIndex + range.lowerBound
        return Data(self[lower..<(lower + range.count)])
    }
}
