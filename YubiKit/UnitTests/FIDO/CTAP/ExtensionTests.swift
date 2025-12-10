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

/// Unit tests for CTAP2 extension types.
@Suite("CTAP2 Extension Tests")
struct ExtensionTests {

    // MARK: - PRF Salt Transformation Tests

    @Test("PRF salt transformation produces 32-byte output")
    func testPRFSaltLength() {
        let secret = Data("test secret".utf8)
        let salt = WebAuthn.Extension.PRF.prfSalt(secret)
        #expect(salt.count == 32)
    }

    @Test("PRF salt transformation is deterministic")
    func testPRFSaltDeterministic() {
        let secret = Data("test secret".utf8)
        let salt1 = WebAuthn.Extension.PRF.prfSalt(secret)
        let salt2 = WebAuthn.Extension.PRF.prfSalt(secret)
        #expect(salt1 == salt2)
    }

    @Test("PRF salt transformation produces different outputs for different inputs")
    func testPRFSaltDifferentInputs() {
        let secret1 = Data("secret one".utf8)
        let secret2 = Data("secret two".utf8)
        let salt1 = WebAuthn.Extension.PRF.prfSalt(secret1)
        let salt2 = WebAuthn.Extension.PRF.prfSalt(secret2)
        #expect(salt1 != salt2)
    }
}
