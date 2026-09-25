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

#if os(macOS)
@testable import YubiKit
#endif

/// CTAPHID transport-layer scenarios.
enum CTAPHIDScenario: CaseIterable, ScenarioSuite {

    case initialize
    case getInfo
    case winkSupported
    case wink
    case echo
    case invalidCommand

    var scenario: Scenario {
        switch self {
        // MARK: - Interface
        case .initialize:
            return Scenario(
                "CTAPHID.Interface.initialize",
                "CTAPHID interface initializes and reports a version and capabilities",
                requirements: Requirements(requiresFIDOTransport: true),
                platform: .macOS
            ) { context in
                #if os(macOS)
                let fido = try await Self.openInterface(context)
                let version = await fido.version
                context.expect(!version.description.isEmpty, "interface should report a version")
                context.expect(await fido.capabilities != [], "interface should report capabilities")
                #endif
            }
        case .getInfo:
            return Scenario(
                "CTAPHID.Interface.getInfo",
                "CTAPHID channel round-trips a CTAP2 getInfo",
                requirements: Requirements(capabilities: [.fido2], requiresFIDOTransport: true),
                platform: .macOS
            ) { context in
                let session = try await context.ctap2Session()
                let info = try await session.getInfo()
                context.expect(!info.versions.isEmpty, "CTAPHID should round-trip a getInfo CBOR response")
                context.log("CTAPHID channel established; getInfo returned \(info.versions.count) versions")
            }
        // MARK: - Capabilities
        case .winkSupported:
            return Scenario(
                "CTAPHID.Capabilities.winkSupported",
                "CTAPHID capability flags report WINK support",
                requirements: Requirements(requiresFIDOTransport: true),
                platform: .macOS
            ) { context in
                #if os(macOS)
                let fido = try await Self.openInterface(context)
                context.expect(await fido.supports(CTAP2.Capabilities.wink), "YubiKey should support WINK")
                #endif
            }
        // MARK: - Commands
        case .wink:
            return Scenario(
                "CTAPHID.Commands.wink",
                "CTAPHID WINK command completes",
                requirements: Requirements(requiresFIDOTransport: true),
                platform: .macOS
            ) { context in
                #if os(macOS)
                let fido = try await Self.openInterface(context)
                guard await fido.supports(CTAP2.Capabilities.wink) else {
                    try context.skip("WINK not supported")
                }
                try await fido.wink()
                context.log("WINK completed")
                #endif
            }
        // MARK: - Ping
        case .echo:
            return Scenario(
                "CTAPHID.Ping.echo",
                "CTAPHID PING echoes the payload unchanged",
                requirements: Requirements(requiresFIDOTransport: true),
                platform: .macOS
            ) { context in
                #if os(macOS)
                let fido = try await Self.openInterface(context)
                let empty = try await fido.ping()
                context.expect(empty.isEmpty, "empty PING should echo an empty payload unchanged")
                let payload = Data([0x01, 0x02, 0x03, 0x04])
                let echoed = try await fido.ping(data: payload)
                context.expect(echoed == payload, "PING should echo the payload unchanged")

                // Also exercise a 12-byte message, 12 spaces, and an empty message.
                for message in [Data("hello world!".utf8), Data("            ".utf8), Data()] {
                    let roundTrip = try await fido.ping(data: message)
                    context.expect(
                        roundTrip == message,
                        "PING should echo back a \(message.count)-byte message unchanged"
                    )
                }
                #endif
            }
        // MARK: - Errors
        case .invalidCommand:
            return Scenario(
                "CTAPHID.Errors.invalidCommand",
                "an invalid CTAPHID command is rejected with a transport error",
                requirements: Requirements(requiresFIDOTransport: true),
                platform: .macOS
            ) { context in
                #if os(macOS)
                let fido = try await Self.openInterface(context)
                do {
                    _ = try await fido.sendAndReceive(cmd: 0xFF, payload: nil)
                    context.record("an invalid CTAPHID command should have failed")
                } catch {
                    context.log("invalid command correctly failed: \(error)")
                }
                #endif
            }
        }
    }

    #if os(macOS)
    private static func openInterface(_ context: Scenario.Context) async throws -> FIDOInterface<CTAP2.SessionError> {
        let connection = try await context.fidoConnection()
        return try await FIDOInterface<CTAP2.SessionError>(connection: connection)
    }
    #endif
}
