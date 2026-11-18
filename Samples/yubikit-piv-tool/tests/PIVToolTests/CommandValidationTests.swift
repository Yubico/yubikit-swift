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

@testable import yubikit_piv_tool

struct CommandValidationTests {
    @Test func rejectOutputFormatBeforeConnecting() async throws {
        let command = try Generate.parse(["9a", "-", "--format", "invalid"])
        do {
            try await command.run()
            Issue.record("Expected an invalid format error")
        } catch let error as ToolError {
            #expect(
                error.localizedDescription == "Invalid format for format.\n\tExpected: PEM, DER.\n\tActual: invalid"
            )
        }
    }

    @Test(arguments: [0, -1])
    func rejectCertificateValidityBeforeConnecting(days: Int) async throws {
        let command = try GenerateCertificate.parse(["9a", "--valid-days=\(days)"])
        do {
            try await command.run()
            Issue.record("Expected an invalid certificate validity error")
        } catch let error as ToolError {
            #expect(error.localizedDescription == "Certificate validity must be greater than zero days.")
        }
    }

    @Test func rejectUnrepresentableCertificateValidityBeforeConnecting() async throws {
        let command = try GenerateCertificate.parse(["9a", "--valid-days=\(Int.max)"])
        do {
            try await command.run()
            Issue.record("Expected an unrepresentable certificate validity error")
        } catch let error as ToolError {
            #expect(error.localizedDescription == "Certificate validity must end before year 10000.")
        }
    }

    @Test(arguments: [16, 24, 32])
    func acceptManagementKeySizes(bytes: Int) throws {
        let key = try ParameterValidator.validateManagementKey(String(repeating: "af", count: bytes))
        #expect(key.count == bytes)
    }

    @Test(arguments: [
        String(repeating: "a", count: 30), String(repeating: "a", count: 47),
        String(repeating: "gg", count: 16), String(repeating: "+f", count: 16),
    ])
    func rejectInvalidManagementKey(hex: String) {
        #expect(throws: ToolError.self) {
            try ParameterValidator.validateManagementKey(hex)
        }
    }
}
