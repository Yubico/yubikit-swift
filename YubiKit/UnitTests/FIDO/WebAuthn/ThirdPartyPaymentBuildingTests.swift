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

/// Verifies that `isPayment: false` (or absent) does NOT append a CTAP
/// `thirdPartyPayment` input. Spec only defines `true` (CTAP 2.3 §12.9);
/// matches python-fido2 behavior, diverges from yubikit-android (which
/// forwards `false`).
@Suite("ThirdPartyPayment Extension Input Building")
struct ThirdPartyPaymentBuildingTests {

    @Test("makeCredential: isPayment=false produces empty ctapInputs")
    func testMakeCredentialIsPaymentFalse() async throws {
        let mock = MockWebAuthnBackend()
        let result = try await mock.buildMakeCredentialExtensions(
            .init(thirdPartyPayment: .init(isPayment: false)),
            allowedExtensions: [.thirdPartyPayment]
        )
        #expect(result.ctapInputs.isEmpty)
    }

    @Test("getAssertion: isPayment=false produces empty ctapInputs")
    func testGetAssertionIsPaymentFalse() async throws {
        let mock = MockWebAuthnBackend()
        let result = try await mock.buildGetAssertionExtensions(
            .init(thirdPartyPayment: .init(isPayment: false)),
            allowCredentials: [],
            selectedCredentialId: nil,
            allowedExtensions: [.thirdPartyPayment]
        )
        #expect(result.ctapInputs.isEmpty)
    }
}
