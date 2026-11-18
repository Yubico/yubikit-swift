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
import YubiKit

@testable import yubikit_piv_tool

struct PostQuantumCommandTests {
    @Test(arguments: [
        ("ml-dsa-44", PIV.KeyType.mlDSA(.mlDSA44)), ("ml-dsa-65", .mlDSA(.mlDSA65)),
        ("ml-dsa-87", .mlDSA(.mlDSA87)), ("ml-kem-512", .mlKEM(.mlKEM512)),
        ("ml-kem-768", .mlKEM(.mlKEM768)), ("ml-kem-1024", .mlKEM(.mlKEM1024)),
    ])
    func acceptPostQuantumAlgorithmSpellings(name: String, expected: PIV.KeyType) throws {
        #expect(try ParameterValidator.validateKeyType(name) == expected)
        #expect(try ParameterValidator.validateKeyType(name.replacingOccurrences(of: "-", with: "")) == expected)
    }

    @Test(arguments: [
        ["--mu", "--context", "ctx"], ["--mu", "--compute-mu"],
        ["--context", String(repeating: "é", count: 128)],
    ])
    func rejectInvalidSigningOptions(options: [String]) {
        #expect(throws: (any Error).self) {
            try Sign.parse(["9a", "-", "-"] + options)
        }
    }

    @Test func protectSecretOutput() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let output = directory.appendingPathComponent("secret")
        let original = Data(repeating: 0x42, count: 32)
        try CommandIO.write(original, to: output.path, secret: true)
        #expect(throws: ToolError.self) { try CommandIO.write(Data(), to: output.path, secret: true) }
        #expect(try Data(contentsOf: output) == original)
        let mode = try FileManager.default.attributesOfItem(atPath: output.path)[.posixPermissions] as? NSNumber
        #expect(mode?.intValue == 0o600)
    }
}
