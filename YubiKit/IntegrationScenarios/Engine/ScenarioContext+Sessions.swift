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
import YubiKit

extension Scenario.Context {

    static let defaultManagementKey =
        Data(hexString: "010203040506070801020304050607080102030405060708")!

    static let defaultTestPin = "11234567"

    static let defaultPIVPin = "123456"

    nonisolated var deviceTransport: DeviceTransport { provider.deviceTransport }

    /// Which transport a Management scenario should drive the application over.
    ///
    /// The SDK deliberately makes the caller pick a connection; a scenario has no such excuse,
    /// because the point is to cover every transport the device actually offers.
    enum ManagementTransportKind: Sendable, CaseIterable {
        case smartCard
        case fidoHID
    }

    /// The default transport. SmartCard is the only one that reaches every Management operation —
    /// `resetDevice` is CCID-only — so unfanned scenarios keep using it.
    func managementSession() async throws -> Management.Session {
        try await managementSession(over: .smartCard)
    }

    func managementSession(over transport: ManagementTransportKind) async throws -> Management.Session {
        switch transport {
        case .smartCard:
            let connection = try await smartCardConnection()
            let scp = try await scpKeyParams()
            return try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
        case .fidoHID:
            return try await Management.Session.makeSession(connection: try await fidoConnection())
        }
    }

    func pivSession(authenticated: Bool = false, reset: Bool = true) async throws -> PIVSession {
        let connection = try await smartCardConnection()
        let scp = try await scpKeyParams()
        let session = try await PIVSession.makeSession(connection: connection, scpKeyParams: scp)
        if reset {
            try await session.reset()
            addTeardown {
                let cleanup = try await PIVSession.makeSession(connection: connection, scpKeyParams: scp)
                try await cleanup.reset()
            }
        }
        if authenticated { try await session.authenticate(with: Self.defaultManagementKey) }
        return session
    }

    func oathSession(reset: Bool = true) async throws -> OATHSession {
        let connection = try await smartCardConnection()
        let scp = try await scpKeyParams()
        let session = try await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
        if reset {
            try await session.reset()
            addTeardown {
                let cleanup = try await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
                try await cleanup.reset()
            }
        }
        return session
    }

    /// Which transport a Yubico OTP scenario should drive the application over. The application is
    /// reachable both ways, and `tests/device/test_otp.py` parameterizes every test across both.
    enum OTPTransportKind: Sendable, CaseIterable {
        case otpHID
        case smartCard
    }

    func otpSession(over transport: OTPTransportKind) async throws -> YubiOTP.Session {
        switch transport {
        case .otpHID:
            return try await YubiOTP.Session.makeSession(connection: try await otpConnection())
        case .smartCard:
            let connection = try await smartCardConnection()
            let scp = try await scpKeyParams()
            return try await YubiOTP.Session.makeSession(connection: connection, scpKeyParams: scp)
        }
    }

    func ctap2Session() async throws -> CTAP2.Session {
        switch provider.ctap2Transport {
        case .ccid:
            let connection = try await smartCardConnection()
            let scp = try await scpKeyParams()
            return try await CTAP2.Session.makeSession(connection: connection, scpKeyParams: scp)
        case .fido:
            let connection = try await fidoConnection()
            return try await CTAP2.Session.makeSession(connection: connection)
        }
    }

    func ctap2SessionAfterNFCReconnect() async throws -> CTAP2.Session {
        await reconnectWhenOverNFC()
        return try await ctap2Session()
    }

    /// Deletes resident credentials; a no-op when no PIN is set or credential management is unsupported.
    func deleteResidentCredentials() async throws {
        let session = try await ctap2Session()
        guard try await session.getInfo().options.clientPin == true else { return }
        guard try await CTAP2.CredentialManagement.isSupported(by: session) else { return }
        let token = try await session.getPinUVToken(
            using: .pin(Self.defaultTestPin),
            permissions: [.credentialManagement]
        )
        let credentialManagement = try await session.credentialManagement(token: token)
        for try await rp in credentialManagement.rps {
            for try await credential in credentialManagement.credentials(for: rp.rpIdHash) {
                try await credentialManagement.deleteCredential(credential.credentialId)
            }
        }
    }

    func webAuthnClient(
        origin: String = "https://example.com",
        allowedExtensions: Set<WebAuthn.Extension.Identifier> = .standard
    ) async throws -> WebAuthn.Client {
        let session = try await ctap2Session()
        return WebAuthn.Client(
            session: session,
            origin: try WebAuthn.Origin(origin),
            allowedExtensions: allowedExtensions,
            isPublicSuffix: { _ in false }
        )
    }

    func webAuthnClientAfterNFCReconnect(
        origin: String = "https://example.com",
        allowedExtensions: Set<WebAuthn.Extension.Identifier> = .standard
    ) async throws -> WebAuthn.Client {
        await reconnectWhenOverNFC()
        return try await webAuthnClient(origin: origin, allowedExtensions: allowedExtensions)
    }
}
