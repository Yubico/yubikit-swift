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
import Testing

@testable import YubiKit

struct COSEKeyTests {
    @Test("COSE.Key round-trip (EC2)")
    func testCOSEKeyEC2RoundTrip() throws {
        let x = Data(repeating: 0x11, count: 32)
        let y = Data(repeating: 0x22, count: 32)

        let original = COSE.Key.ec2(alg: .es256, kid: nil, crv: 1, x: x, y: y)
        let encoded = original.cbor()
        let decoded = try #require(COSE.Key(cbor: encoded))

        #expect(decoded == original)
    }

    @Test("COSE.Key round-trip (OKP)")
    func testCOSEKeyOKPRoundTrip() throws {
        let keyData = Data(repeating: 0x33, count: 32)

        let original = COSE.Key.okp(alg: .edDSA, kid: nil, crv: 6, x: keyData)
        let encoded = original.cbor()
        let decoded = try #require(COSE.Key(cbor: encoded))

        #expect(decoded == original)
    }

    @Test("COSE.Key round-trip (RSA)")
    func testCOSEKeyRSARoundTrip() throws {
        let n = Data(repeating: 0x44, count: 256)  // 2048-bit
        let e = Data([0x01, 0x00, 0x01])  // 65537

        let original = COSE.Key.rsa(alg: .rs256, kid: nil, n: n, e: e)
        let encoded = original.cbor()
        let decoded = try #require(COSE.Key(cbor: encoded))

        #expect(decoded == original)
    }

}
