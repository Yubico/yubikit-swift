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

// MARK: - Device Discovery and Information Commands

struct List: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "List all connected YubiKey devices"
    )

    func run() async throws {
        do {
            // Enumerate all available Smart Card slots
            let availableDevices = try await USBSmartCardConnection.availableDevices

            if availableDevices.isEmpty {
                // No YubiKeys found
                return
            }

            // Connect to each YubiKey and retrieve device information
            for slot in availableDevices {
                do {
                    // Establish Smart Card connection to the YubiKey
                    let connection = try await USBSmartCardConnection.connection(slot: slot)

                    // Create management session to access device metadata
                    let session = try await ManagementSession.session(withConnection: connection)

                    // Get basic device info: form factor (5A, 5C, etc), firmware version, serial number
                    let deviceInfo = try await session.getDeviceInfo()
                    print("YubiKey \(deviceInfo.formFactor) (\(deviceInfo.version)) Serial: \(deviceInfo.serialNumber)")
                }
            }
        } catch {
            throw PIVToolError.generic("Could not enumerate devices: \(error.localizedDescription)")
        }
    }
}

struct Info: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Display comprehensive PIV application status and information"
    )

    func run() async throws {
        // Connect to PIV application on the YubiKey
        let session = try await PIVSession.shared()

        print("PIV version: \(session.version.major).\(session.version.minor).\(session.version.micro)")

        // Verify YubiKey supports metadata operations
        guard session.supports(PIVSessionFeature.metadata) else {
            throw PIVToolError.unsupportedOperation(
                operation: "metadata",
                reason: "This YubiKey does not support metadata operations"
            )
        }

        // Get PIN retry counter and whether it's still the factory default
        let pinMetadata: PIV.PinPukMetadata
        do {
            pinMetadata = try await session.getPinMetadata()
        }
        print("PIN tries remaining: \(pinMetadata.retriesRemaining)/\(pinMetadata.retriesTotal)")

        // Get PUK status: retry counter and default status
        let pukMetadata: PIV.PinPukMetadata
        do {
            pukMetadata = try await session.getPukMetadata()
        }
        print("PUK tries remaining: \(pukMetadata.retriesRemaining)/\(pukMetadata.retriesTotal)")
        if pukMetadata.isDefault {
            print("WARNING! Using default PUK")
        }

        // whether it's still the factory default 3DES key
        let mgmtKeyMetadata: PIV.ManagementKeyMetadata
        do {
            mgmtKeyMetadata = try await session.getManagementKeyMetadata()
        }
        if mgmtKeyMetadata.isDefault {
            print("WARNING! Using default Management key")
        }
    }
}

struct Reset: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Reset PIV application to factory default state"
    )

    func run() async throws {
        let session = try await PIVSession.shared()

        // Perform PIV factory reset - this is destructive and irreversible
        // Deletes ALL keys, certificates, and resets all credentials to factory defaults
        do {
            try await session.reset()
        }

        // Inform user about the reset completion and new default credentials
        print("Resetting PIV data...")
        print("Reset complete. All PIV data has been cleared from the YubiKey.")
        print("Your YubiKey now has the default PIN, PUK and Management Key:")
        print("    PIN:    123456")
        print("    PUK:    12345678")
        print("    Management Key:    010203040506070801020304050607080102030405060708")
    }
}
