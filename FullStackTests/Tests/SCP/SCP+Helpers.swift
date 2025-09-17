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

// MARK: - SCP Test Support

var connection: SmartCardConnection {
    _connection!
}

var defaultKeyParams: SCP03KeyParams {
    _defaultKeyParams
}

func runSCPTest(
    test: @escaping () async throws -> Void
) async throws {
    let connection = try await TestableConnection.shared()

    // reset YubiKey's SCP state to the factory default
    try await SecurityDomainSession.session(withConnection: connection).reset()

    _connection = connection
    try await test()
}

private var _connection: SmartCardConnection!

private let _defaultKeyParams: SCP03KeyParams = {
    let defaultKeyRef = SCPKeyRef(kid: .scp03, kvn: 0xff)
    return try! SCP03KeyParams(
        keyRef: defaultKeyRef,
        staticKeys: StaticKeys.defaultKeys()
    )
}()
