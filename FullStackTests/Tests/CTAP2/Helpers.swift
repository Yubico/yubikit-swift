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

@testable import FullStackTests
@testable import YubiKit

// MARK: - CTAP2 Test Configuration
let defaultTestPin = "11234567"

#if os(macOS)
let ctap2Transport: CTAP2Transport = .hid
#elseif os(iOS)
let ctap2Transport: CTAP2Transport = .smartCard(scp: false)
#endif

// MARK: - CTAP2 Session Helpers

// Simple session helper for tests with single or no UP operation.
func withCTAP2Session<T>(
    _ body: (CTAP2.Session) async throws -> T
) async throws -> T {
    let (connection, session) = try await createCTAP2Session()
    let result = try await body(session)
    await connection.close(error: nil)
    return result
}

// Session helper with reconnect for multi-UP tests. Over NFC, call reconnectWhenOverNFC before each UP.
func withReconnectableCTAP2Session<T>(
    _ body: (_ session: CTAP2.Session, _ reconnectWhenOverNFC: () async throws -> CTAP2.Session) async throws -> T
) async throws -> T {
    let state = CTAP2SessionState()
    (state.connection, state.session) = try await createCTAP2Session()

    let reconnectWhenOverNFC: () async throws -> CTAP2.Session = {
        if ctap2Transport.isNFC {
            await state.connection?.close(error: nil)
            (state.connection, state.session) = try await createCTAP2Session()
        }
        return state.session!
    }

    let result = try await body(state.session!, reconnectWhenOverNFC)
    await state.connection?.close(error: nil)
    return result
}

private class CTAP2SessionState {
    var connection: (any Connection)?
    var session: CTAP2.Session?
}

private func createCTAP2Session() async throws -> (any Connection, CTAP2.Session) {
    switch ctap2Transport {
    #if os(macOS)
    case .hid:
        let connection = try await HIDFIDOConnection()
        let session = try await CTAP2.Session.makeSession(connection: connection)
        return (connection, session)
    #endif

    case .smartCard(let scp):
        let connection = try await TestableConnection.create(with: .smartCard)
        let scpKeyParams: SCPKeyParams? = scp ? try await getSCP11bKeyParams(connection: connection) : nil
        let session = try await CTAP2.Session.makeSession(connection: connection, scpKeyParams: scpKeyParams)
        return (connection, session)

    #if os(iOS)
    case .nfc(let scp):
        let connection = try await TestableConnection.create(with: .nfc)
        let scpKeyParams: SCPKeyParams? = scp ? try await getSCP11bKeyParams(connection: connection) : nil
        let session = try await CTAP2.Session.makeSession(connection: connection, scpKeyParams: scpKeyParams)
        return (connection, session)

    case .lightning(let scp):
        let connection = try await TestableConnection.create(with: .lightning)
        let scpKeyParams: SCPKeyParams? = scp ? try await getSCP11bKeyParams(connection: connection) : nil
        let session = try await CTAP2.Session.makeSession(connection: connection, scpKeyParams: scpKeyParams)
        return (connection, session)
    #endif
    }
}

// Reads SCP11b key params from the YubiKey's Security Domain.
private func getSCP11bKeyParams(connection: SmartCardConnection) async throws -> SCP11KeyParams {
    let securityDomainSession = try await SecurityDomainSession.makeSession(connection: connection)
    let scpKeyRef = SCPKeyRef(kid: .scp11b, kvn: 0x01)
    let certificates = try await securityDomainSession.getCertificateBundle(for: scpKeyRef)
    guard let last = certificates.last,
        case let .ec(publicKey) = last.publicKey
    else {
        throw CTAP2.SessionError.featureNotSupported(source: .here())
    }
    return try SCP11KeyParams(keyRef: scpKeyRef, pkSdEcka: publicKey)
}

// MARK: - Transport Configuration

enum CTAP2Transport {
    #if os(macOS)
    case hid
    #endif
    case smartCard(scp: Bool = false)
    #if os(iOS)
    case nfc(scp: Bool = false)
    case lightning(scp: Bool = false)
    #endif

    var isNFC: Bool {
        #if os(iOS)
        if case .nfc = self { return true }
        #endif
        return false
    }
}
