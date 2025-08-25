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

extension PIV.Slot {
    // Human-readable name for PIV slot
    var displayName: String {
        switch self {
        case .authentication: return "AUTHENTICATION"
        case .signature: return "DIGITAL SIGNATURE"
        case .keyManagement: return "KEY MANAGEMENT"
        case .cardAuth: return "CARD AUTHENTICATION"
        case .attestation: return "ATTESTATION"
        }
    }
}

extension PIVSession {
    func authenticateWithManagementKey(_ managementKeyHex: String?) async throws {
        guard let managementKeyHex = managementKeyHex else { return }

        let mgmtKeyData = try ParameterValidator.validateManagementKey(managementKeyHex)

        do {
            try await authenticateWith(managementKey: mgmtKeyData)
        } catch {
            throw PIVToolError.managementKeyAuthenticationFailed
        }
    }

    func verifyPinIfProvided(_ pin: String?) async throws {
        guard let pin = pin else { return }

        let result = try await verifyPin(pin)
        switch result {
        case .success:
            break
        case let .fail(retries):
            throw PIVToolError.pinVerificationFailed(retriesRemaining: retries)
        case .pinLocked:
            throw PIVToolError.pinBlocked
        }
    }
}
