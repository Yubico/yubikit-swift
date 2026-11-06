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

struct SmartCardCommandChainingTests {
    // Android 3.3.0 SmartCardProtocolTest: same firmware, lengths, headers and byte pattern.
    private static func pattern(_ count: Int) -> Data {
        Data((0..<count).map { UInt8(truncatingIfNeeded: $0 * 31 + 7) })
    }

    @Test(
        arguments: [
            (nil, 600, true),
            ("5.7.2", 3055, false), ("5.7.2", 3056, true),
            ("6.0.0", 4911, false), ("6.0.0", 4912, true),
        ] as [(String?, Int, Bool)]
    )
    func limits(firmware: String?, length: Int, chained: Bool) async throws {
        let chunks = chained ? (length + 254) / 255 : 1
        let mock = MockSmartCardConnection(
            responses:
                Array(repeating: Data([0x90, 0x00]), count: chunks)
                + [Data([1, 2, 3, 0x61, 2]), Data([4, 5, 0x90, 0x00])]
        )
        let interface = try await SmartCardInterface<PIVSessionError>(connection: mock, application: .piv)
        if let firmware { await interface.configure(version: Version(firmware)!) }
        let payload = Self.pattern(length)
        let continuation: UInt8 = firmware == nil ? 0xa5 : 0xc0
        let response: Data = try await interface.send(
            apdu: APDU(cla: 0x80, ins: 1, p1: 2, p2: 3, command: payload),
            insSendRemaining: continuation
        )
        #expect(response == Data([1, 2, 3, 4, 5]))
        let requests = Array(await mock.sentRequests.dropFirst())
        #expect(requests.last == Data([0, continuation, 0, 0, 0]))
        #expect(requests.count == chunks + 1)
        if chained {
            var reconstructed = Data()
            for (index, request) in requests.dropLast().enumerated() {
                #expect(request.prefix(4) == Data([index == chunks - 1 ? 0x80 : 0x90, 1, 2, 3]))
                #expect(request.count == 5 + Int(request[4]))
                #expect(index == chunks - 1 || request[4] == 255)
                reconstructed.append(request.dropFirst(5))
            }
            #expect(reconstructed == payload)
        } else {
            #expect(requests[0] == Data([0x80, 1, 2, 3, 0, UInt8(length >> 8), UInt8(length & 255)]) + payload)
        }
    }

    @Test("Stop a command chain at the first error")
    func intermediateError() async throws {
        let mock = MockSmartCardConnection(responses: [
            Data([0x90, 0]), Data([0x90, 0]), Data([0x69, 0x82]),
        ])
        let interface = try await SmartCardInterface<PIVSessionError>(connection: mock, application: .piv)
        await interface.configure(version: Version("5.7.2")!)
        await #expect {
            let _: Data = try await interface.send(
                apdu: APDU(
                    cla: 0x80,
                    ins: 1,
                    p1: 4,
                    p2: 5,
                    command: Self.pattern(5000)
                )
            )
        } throws: { ($0 as? PIVSessionError)?.responseStatus?.rawStatus == 0x6982 }
        #expect(await mock.sendCount == 3)
    }

    @Test("Secure messaging protects the complete command before splitting it")
    func secureCommand() async throws {
        // Android ScpProcessorTest.commandLargerThanASingleApduIsPassedOn uses 10,000 bytes.
        let mock = ChainedSCPConnection()
        let interface = try await SmartCardInterface<PIVSessionError>(
            connection: mock,
            application: .piv,
            keyParams: SCP03KeyParams(keyRef: SCPKeyRef(kid: .scp03, kvn: 1), staticKeys: .defaultKeys())
        )
        await interface.configure(version: Version("5.7.2")!)
        let message = Self.pattern(10_000)
        await #expect {
            let _: Data = try await interface.send(apdu: APDU(cla: 0, ins: 1, p1: 2, p2: 3, command: message))
        } throws: { ($0 as? PIVSessionError)?.responseStatus?.rawStatus == 0x6a88 }
        let (senc, smac, chain, requests) = await mock.captured()
        var protected = Data()
        for (index, request) in requests.enumerated() {
            #expect(request[0] == (index == requests.count - 1 ? 0x04 : 0x14))
            #expect(request.count == 5 + Int(request[4]))
            protected.append(request.dropFirst(5))
        }
        #expect(protected.count == 10_024)
        let header = Data([4, 1, 2, 3, 0, UInt8(protected.count >> 8), UInt8(protected.count & 255)])
        let mac = try (chain + header + protected.dropLast(8)).aescmac(key: smac)
        #expect(protected.suffix(8) == mac.prefix(8))
        let iv = try (Data(count: 15) + Data([1])).encryptAES(key: senc, mode: .ecb)
        #expect(try Data(protected.dropLast(8)).decryptAES(key: senc, mode: .cbc(iv: iv)) == message.bitPadded())
    }
}

private actor ChainedSCPConnection: SmartCardConnection {
    private var keys: SCPSessionKeys?
    private var chain = Data()
    private var commands: [Data] = []
    init() {}
    static func makeConnection() async throws(SmartCardConnectionError) -> Self { Self() }

    func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        do {
            switch data[1] {
            case 0xa4: return Data([0x90, 0])
            case 0x50:
                let challenge = Data(repeating: 0x12, count: 8)
                let context = Data(data.suffix(8)) + challenge
                let keys = try StaticKeys.defaultKeys().derive(context: context)
                self.keys = keys
                let cryptogram = try StaticKeys.deriveKey(key: keys.smac, t: 0, context: context, l: 0x40)
                return Data(count: 10) + Data([1, 3, 0]) + challenge + cryptogram + Data([0x90, 0])
            case 0x82:
                chain = try (Data(count: 16) + data.dropLast(8)).aescmac(key: keys!.smac)
                return Data([0x90, 0])
            default:
                commands.append(data)
                return data[0] & 0x10 != 0 ? Data([0x90, 0]) : Data([0x6a, 0x88])
            }
        } catch {
            throw .transmitFailed("Test SCP initialization failed", error)
        }
    }
    func captured() -> (Data, Data, Data, [Data]) { (keys!.senc, keys!.smac, chain, commands) }
    func close(error: Error?) async {}
    func waitUntilClosed() async -> Error? { nil }
}
