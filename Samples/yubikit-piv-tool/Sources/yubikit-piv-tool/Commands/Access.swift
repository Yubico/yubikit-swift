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

import ArgumentParser
import Foundation
import YubiKit

// MARK: - Access Credential Management Commands

struct Access: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage PIV access credentials (PIN, PUK, management key)",
        subcommands: [
            ChangePin.self,
            ChangePuk.self,
            ChangeManagementKey.self,
            UnblockPin.self,
        ]
    )
}

struct ChangePin: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "change-pin",
        abstract: "Change the PIV PIN"
    )

    @Option(name: [.customShort("P"), .customLong("pin")], help: "Current PIN for authentication")
    var pin: String?

    @Option(name: [.customShort("n"), .customLong("new-pin")], help: "New PIN to set")
    var newPin: String?

    func run() async throws {
        // Validate required parameters
        guard let currentPin = pin else {
            exitWithError("Missing required parameter: pin.\n\tUse --pin to provide current PIN")
        }
        guard let newPin = newPin else {
            exitWithError("Missing required parameter: new-pin.\n\tUse --new-pin to provide new PIN (6-8 characters)")
        }

        // Validate PIN format and length
        ParameterValidator.validatePin(newPin)

        let session = try await PIVSession.shared()

        // Attempt PIN change - requires current PIN for authentication
        // This atomically verifies the old PIN and sets the new one
        do {
            _ = try await session.changePin(from: currentPin, to: newPin)
            print("New PIN set.")
        } catch {
            handlePIVError(error)
        }
    }
}

struct ChangePuk: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "change-puk",
        abstract: "Change the PIV PUK (PIN Unblocking Key)"
    )

    @Option(name: [.customShort("p"), .customLong("puk")], help: "Current PUK for authentication")
    var puk: String?

    @Option(name: [.customShort("n"), .customLong("new-puk")], help: "New PUK to set (used to unblock PIN)")
    var newPuk: String?

    func run() async throws {
        // Validate required parameters
        guard let currentPuk = puk else {
            exitWithError("Missing required parameter: puk.\n\tUse --puk to provide current PUK")
        }
        guard let newPuk = newPuk else {
            exitWithError("Missing required parameter: new-puk.\n\tUse --new-puk to provide new PUK")
        }

        // Validate PUK format and length
        ParameterValidator.validatePuk(newPuk)

        let session = try await PIVSession.shared()

        // Attempt PUK change - requires current PUK for authentication
        // PUK is used to unblock PIN when retry counter reaches zero
        do {
            _ = try await session.changePuk(from: currentPuk, to: newPuk)
            print("New PUK set.")
        } catch {
            handlePIVError(error, context: "PUK")
        }
    }
}

// Hardcoded to 3DES for now
struct ChangeManagementKey: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "change-management-key",
        abstract: "Change the PIV management key"
    )

    @Option(
        name: [.customShort("m"), .customLong("management-key")],
        help: "Current management key"
    )
    var managementKey: String?

    @Option(
        name: [.customShort("n"), .customLong("new-management-key")],
        help: "New management key"
    )
    var newManagementKey: String?

    func run() async throws {
        // Validate required parameters
        guard let currentKey = managementKey else {
            exitWithError(
                "Missing required parameter: management-key.\n\tUse --management-key to provide current management key"
            )
        }
        guard let newKey = newManagementKey else {
            exitWithError(
                "Missing required parameter: new-management-key.\n\tUse --new-management-key to provide new management key"
            )
        }

        // Parse and validate management keys
        let currentKeyData = ParameterValidator.validateManagementKey(currentKey)
        let newKeyData = ParameterValidator.validateManagementKey(newKey)

        let session = try await PIVSession.shared()

        // authenticate with current key, then set new key
        do {
            try await session.authenticate(with: currentKeyData)
            try await session.setManagementKey(newKeyData, type: .tripleDES, requiresTouch: false)
            print("New management key set.")
        } catch {
            exitWithError("Authentication with management key failed.")
        }
    }
}

struct UnblockPin: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "unblock-pin",
        abstract: "Unblock the PIN using the PUK"
    )

    @Option(name: [.customShort("p"), .customLong("puk")], help: "PUK for unblocking (resets PIN retry counter)")
    var puk: String?

    @Option(name: [.customShort("n"), .customLong("new-pin")], help: "New PIN to set after unblocking")
    var newPin: String?

    func run() async throws {
        // Validate required parameters
        guard let puk = puk else {
            exitWithError("Missing required parameter: puk.\n\tUse --puk to provide PUK for unblocking")
        }
        guard let newPin = newPin else {
            exitWithError("Missing required parameter: new-pin.\n\tUse --new-pin to set new PIN after unblocking")
        }

        ParameterValidator.validatePin(newPin)

        let session = try await PIVSession.shared()

        do {
            try await session.unblockPin(with: puk, newPin: newPin)
            print("PIN unblocked and set to new value.")
        } catch {
            handlePIVError(error, context: "PUK")
        }
    }
}
