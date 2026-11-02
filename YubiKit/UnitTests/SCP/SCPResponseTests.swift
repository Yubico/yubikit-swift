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

struct SCPResponseTests {
    @Test(
        "bare success and warnings require R-MAC; bare errors pass through",
        arguments: [UInt16(0x9000), 0x6285, 0x63c0, 0x6982]
    )
    func emptyResponse(sw: UInt16) async throws {
        // Initialization also checks that bare EXTERNAL AUTHENTICATE success is accepted.
        let interface = try await SmartCardInterface<OATHSessionError>(
            connection: BareSCPResponseConnection(sw: sw),
            application: .oath,
            keyParams: SCP03KeyParams(keyRef: SCPKeyRef(kid: .scp03, kvn: 1), staticKeys: .defaultKeys())
        )
        do {
            let _: Data = try await interface.send(apdu: APDU(cla: 0, ins: 0xca, p1: 0, p2: 0))
            Issue.record("Expected the bare response to fail")
        } catch {
            if sw == 0x6982 {
                #expect(error.responseStatus?.rawStatus == sw)
            } else if case .scpError(.responseParseError, _) = error {
                // Missing R-MAC was rejected before interpreting the status.
            } else {
                Issue.record("Expected an SCP authentication failure, got \(error)")
            }
        }
    }
}

private actor BareSCPResponseConnection: SmartCardConnection {
    let sw: UInt16

    init(sw: UInt16) { self.sw = sw }
    init() async throws(SmartCardConnectionError) { fatalError("Use init(sw:)") }
    static func makeConnection() async throws(SmartCardConnectionError) -> BareSCPResponseConnection {
        fatalError("Use init(sw:)")
    }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        switch data[1] {
        case 0xa4, 0x82:
            return Data([0x90, 0x00])
        case 0x50:
            // Complete SCP03 initialization using the host's random challenge.
            let challenge = Data(repeating: 0x12, count: 8)
            let context = Data(data.suffix(8)) + challenge
            do {
                let keys = try StaticKeys.defaultKeys().derive(context: context)
                let cryptogram = try StaticKeys.deriveKey(key: keys.smac, t: 0, context: context, l: 0x40)
                return Data(count: 10) + Data([1, 3, 0]) + challenge + cryptogram + Data([0x90, 0x00])
            } catch {
                throw .transmitFailed("Test SCP initialization failed", error)
            }
        default:
            return sw.bigEndian.data
        }
    }

    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }
}
