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

import CryptoTokenKit
import Foundation
import Testing

@testable import YubiKit

struct PIVPostQuantumTests {
    // Android 3.3.0: PivSessionPostQuantumTest and PublicKeyValuesTest, with PostQuantumTestKeys.
    // Wire identifiers also match Rust yubikit 1.0.0-beta.0 (f59e6fed), piv.rs.
    struct Fixture: Sendable {
        let type: PIV.KeyType
        let algorithm: UInt8
        let publicLength: Int
        let seedLength: Int
        let publicTag: TKTLVTag
        let importTag: UInt8
        let spkiPrefix: String

        func publicKey(_ data: Data) -> PublicKey? {
            switch type {
            case .mlDSA(let params): MLDSA.PublicKey(keyData: data, parameterSet: params).map(PublicKey.mlDSA)
            case .mlKEM(let params): MLKEM.PublicKey(keyData: data, parameterSet: params).map(PublicKey.mlKEM)
            default: nil
            }
        }

        func importSeed(_ seed: Data, into session: PIVSession) async throws {
            switch type {
            case .mlDSA(let params):
                let key = try #require(MLDSA.PrivateKey(seed: seed, parameterSet: params))
                #expect(
                    try await session.putPrivateKey(
                        key,
                        in: .authentication,
                        pinPolicy: .defaultPolicy,
                        touchPolicy: .defaultPolicy
                    ) == .mlDSA(params)
                )
            case .mlKEM(let params):
                let key = try #require(MLKEM.PrivateKey(seed: seed, parameterSet: params))
                #expect(
                    try await session.putPrivateKey(
                        key,
                        in: .authentication,
                        pinPolicy: .defaultPolicy,
                        touchPolicy: .defaultPolicy
                    ) == .mlKEM(params)
                )
            default: Issue.record("Unexpected fixture type")
            }
        }
    }

    static let fixtures: [Fixture] = [
        Fixture(
            type: .mlDSA(.mlDSA44),
            algorithm: 0xe2,
            publicLength: 1312,
            seedLength: 32,
            publicTag: 0x87,
            importTag: 0x09,
            spkiPrefix: "30820532300b06096086480165030403110382052100"
        ),
        Fixture(
            type: .mlDSA(.mlDSA65),
            algorithm: 0xe3,
            publicLength: 1952,
            seedLength: 32,
            publicTag: 0x87,
            importTag: 0x09,
            spkiPrefix: "308207b2300b0609608648016503040312038207a100"
        ),
        Fixture(
            type: .mlDSA(.mlDSA87),
            algorithm: 0xe4,
            publicLength: 2592,
            seedLength: 32,
            publicTag: 0x87,
            importTag: 0x09,
            spkiPrefix: "30820a32300b060960864801650304031303820a2100"
        ),
        Fixture(
            type: .mlKEM(.mlKEM512),
            algorithm: 0xe5,
            publicLength: 800,
            seedLength: 64,
            publicTag: 0x88,
            importTag: 0x0a,
            spkiPrefix: "30820332300b06096086480165030404010382032100"
        ),
        Fixture(
            type: .mlKEM(.mlKEM768),
            algorithm: 0xe6,
            publicLength: 1184,
            seedLength: 64,
            publicTag: 0x88,
            importTag: 0x0a,
            spkiPrefix: "308204b2300b0609608648016503040402038204a100"
        ),
        Fixture(
            type: .mlKEM(.mlKEM1024),
            algorithm: 0xe7,
            publicLength: 1568,
            seedLength: 64,
            publicTag: 0x88,
            importTag: 0x0a,
            spkiPrefix: "30820632300b06096086480165030404030382062100"
        ),
    ]

    private static func pattern(_ length: Int, _ start: Int) -> Data {
        Data((0..<length).map { UInt8(truncatingIfNeeded: start + $0) })
    }

    private static func frame(_ data: Data = Data()) -> Data { data + Data([0x90, 0]) }

    private static func card(_ replies: [Data], firmware: [UInt8] = [6, 0, 0]) -> MockSmartCardConnection {
        MockSmartCardConnection(responses: [frame(), frame(Data(firmware))] + replies.map(frame))
    }

    private static func body(_ request: Data) -> Data {
        Data(request.dropFirst(request[4] == 0 ? 7 : 5))
    }

    private static func auth(_ tag: TKTLVTag, _ value: Data) -> Data {
        TKBERTLVRecord(
            tag: 0x7c,
            records: [
                TKBERTLVRecord(tag: 0x82, value: Data()), TKBERTLVRecord(tag: tag, value: value),
            ]
        ).data
    }

    private static func reply(_ value: Data) -> Data {
        TKBERTLVRecord(tag: 0x7c, value: TKBERTLVRecord(tag: 0x82, value: value).data).data
    }

    @Test(arguments: fixtures)
    func keyEncoding(fixture: Fixture) throws {
        let data = Self.pattern(fixture.publicLength, 0)
        let key = try #require(fixture.publicKey(data))
        #expect(key.spki == Data(hexEncodedString: fixture.spkiPrefix)! + data)
    }

    @Test("Reject malformed raw keys and seeds")
    func invalidKeySizes() {
        // Android PublicKeyValuesTest uses 32-byte inputs for these two parameter sets.
        #expect(MLDSA.PublicKey(keyData: Data(count: 32), parameterSet: .mlDSA65) == nil)
        #expect(MLKEM.PublicKey(keyData: Data(count: 32), parameterSet: .mlKEM768) == nil)
        #expect(MLDSA.PrivateKey(seed: Data(count: 31), parameterSet: .mlDSA65) == nil)
        #expect(MLKEM.PrivateKey(seed: Data(count: 63), parameterSet: .mlKEM768) == nil)
    }

    @Test(arguments: fixtures)
    func generationImportAndMetadata(fixture: Fixture) async throws {
        let keyData = Self.pattern(fixture.publicLength, 3)
        let keyTLV = TKBERTLVRecord(tag: fixture.publicTag, value: keyData).data
        let metadata =
            TKBERTLVRecord(tag: 1, value: Data([fixture.algorithm])).data
            + TKBERTLVRecord(tag: 2, value: Data([0, 0])).data
            + TKBERTLVRecord(tag: 3, value: Data([1])).data
            + TKBERTLVRecord(tag: 4, value: keyTLV).data
        let mock = Self.card([TKBERTLVRecord(tag: 0x7f49, value: keyTLV).data, metadata, Data()])
        let session = try await PIVSession.makeSession(connection: mock)
        #expect(try await session.generateKey(in: .signature, type: fixture.type) == fixture.publicKey(keyData))
        let info = try await session.getMetadata(in: .signature)
        #expect(info.keyType == fixture.type)
        #expect(info.publicKey == fixture.publicKey(keyData))
        let seed = Self.pattern(fixture.seedLength, 1)
        try await fixture.importSeed(seed, into: session)
        let requests = await mock.sentRequests
        #expect(requests[2] == Data([0, 0x47, 0, 0x9c, 5, 0xac, 3, 0x80, 1, fixture.algorithm]))
        #expect(
            requests[4] == Data([
                0, 0xfe, fixture.algorithm, 0x9a, UInt8(fixture.seedLength + 2),
                fixture.importTag, UInt8(fixture.seedLength),
            ]) + seed
        )
    }

    @Test(arguments: [fixtures[0], fixtures[4]])
    func unsupportedFirmware(fixture: Fixture) async throws {
        let mock = Self.card([], firmware: [5, 7, 4])
        let session = try await PIVSession.makeSession(connection: mock)
        await #expect { try await session.generateKey(in: .signature, type: fixture.type) } throws: {
            guard case PIVSessionError.featureNotSupported = $0 else { return false }
            return true
        }
        await #expect { try await fixture.importSeed(Data(count: fixture.seedLength), into: session) } throws: {
            guard case PIVSessionError.featureNotSupported = $0 else { return false }
            return true
        }
        #expect(await mock.sendCount == 2)
    }

    // The 4,000-byte case checks configuration through a PIV session.
    @Test(arguments: [0, 4000])
    func messageIsSentUnchanged(length: Int) async throws {
        let signature = Self.pattern(100, 9)
        let mock = Self.card([Self.reply(signature)])
        let session = try await PIVSession.makeSession(connection: mock)
        let message = Self.pattern(length, 1)
        #expect(try await session.sign(message, in: .signature, keyType: .mlDSA(.mlDSA44)) == signature)
        let request = try #require(await mock.sentRequests.last)
        #expect(request.prefix(4) == Data([0, 0x87, 0xe2, 0x9c]))
        #expect(Self.body(request) == Self.auth(0x81, message))
    }

    @Test("Context and external-mu signing match Android operands")
    func signingOperands() async throws {
        let signature = Self.pattern(100, 9)
        let mock = Self.card(Array(repeating: Self.reply(signature), count: 2))
        let session = try await PIVSession.makeSession(connection: mock)
        let message = Self.pattern(40, 1)
        let context = Self.pattern(255, 50)
        #expect(
            try await session.sign(message, in: .signature, keyType: .mlDSA(.mlDSA87), context: context) == signature
        )
        let mu = Self.pattern(64, 20)
        #expect(try await session.sign(externalMu: mu, in: .signature, keyType: .mlDSA(.mlDSA44)) == signature)
        let requests = await mock.sentRequests
        let expected = TKBERTLVRecord(
            tag: 0x7c,
            records: [
                TKBERTLVRecord(tag: 0x82, value: Data()),
                TKBERTLVRecord(tag: 0x87, value: context), TKBERTLVRecord(tag: 0x81, value: message),
            ]
        ).data
        #expect(requests[2].prefix(4) == Data([0, 0x87, 0xe4, 0x9c]))
        #expect(Self.body(requests[2]) == expected)
        #expect(requests[3].prefix(4) == Data([0, 0x87, 0xe2, 0x9c]))
        #expect(Self.body(requests[3]) == Self.auth(0x88, mu))
    }

    @Test(arguments: [
        (MLKEM.ParameterSet.mlKEM512, 768, UInt8(0xe5)), (.mlKEM768, 1088, 0xe6), (.mlKEM1024, 1568, 0xe7),
    ])
    func decapsulation(parameterSet: MLKEM.ParameterSet, length: Int, algorithm: UInt8) async throws {
        let secret = Self.pattern(32, 77)
        let ciphertext = Self.pattern(length, 2)
        let mock = Self.card([Self.reply(secret)])
        let session = try await PIVSession.makeSession(connection: mock)
        #expect(try await session.decapsulate(ciphertext, in: .keyManagement, keyType: .mlKEM(parameterSet)) == secret)
        let request = try #require(await mock.sentRequests.last)
        #expect(request.prefix(4) == Data([0, 0x87, algorithm, 0x9d]))
        #expect(Self.body(request) == Self.auth(0x86, ciphertext))
    }

    @Test("Invalid operation inputs fail before I/O")
    func invalidOperands() async throws {
        let mock = Self.card([])
        let session = try await PIVSession.makeSession(connection: mock)
        await #expect {
            try await session.sign(Data(), in: .signature, keyType: .mlDSA(.mlDSA44), context: Data(count: 256))
        } throws: { if case PIVSessionError.illegalArgument = $0 { true } else { false } }
        for length in [63, 65] {
            await #expect {
                try await session.sign(externalMu: Data(count: length), in: .signature, keyType: .mlDSA(.mlDSA44))
            } throws: { if case PIVSessionError.illegalArgument = $0 { true } else { false } }
        }
        await #expect {
            try await session.decapsulate(Data(count: 768), in: .keyManagement, keyType: .mlKEM(.mlKEM768))
        } throws: { if case PIVSessionError.illegalArgument = $0 { true } else { false } }
        #expect(await mock.sendCount == 2)
    }
}
