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

enum PIVToolError: LocalizedError, CustomStringConvertible {
    // Input validation errors
    case missingRequiredParameter(parameter: String, help: String? = nil)
    case invalidFormat(parameter: String, expected: String, actual: String? = nil)
    case invalidSlot(slot: String)
    case invalidKeyType(keyType: String)
    case invalidPinLength(actual: Int, min: Int = 6, max: Int = 8)
    case invalidPukLength(actual: Int, min: Int = 6, max: Int = 8)
    case invalidManagementKeyFormat(expected: String = "48 hex characters for 3DES")
    case invalidHashAlgorithm(algorithm: String)

    // Authentication errors with retry information
    case pinVerificationFailed(retriesRemaining: Int?)
    case pukVerificationFailed(retriesRemaining: Int?)
    case managementKeyAuthenticationFailed
    case pinBlocked
    case pukBlocked

    // Operation errors
    case slotEmpty(slot: String)
    case slotAlreadyContains(slot: String, type: String)
    case unsupportedOperation(operation: String, reason: String)
    case certificateNotFound(slot: String)
    case keyGenerationFailed(slot: String, algorithm: String, reason: String? = nil)
    case importFailed(reason: String)
    case exportFailed(reason: String)
    case attestationNotSupported(slot: String)

    // File I/O errors
    case fileNotFound(path: String)
    case fileReadError(path: String, reason: String? = nil)
    case fileWriteError(path: String, reason: String? = nil)
    case invalidFileFormat(path: String, expected: String)

    case generic(_ message: String)

    var description: String {
        switch self {
        // Input validation
        case let .missingRequiredParameter(param, help):
            var base = "Missing required parameter: --\(param)"
            if let help = help {
                base += "\n\t\(help)"
            }
            return base

        case let .invalidFormat(param, expected, actual):
            var msg = "Invalid format for \(param): expected \(expected)"
            if let actual = actual {
                msg += ", got '\(actual)'"
            }
            return msg

        case let .invalidSlot(slot):
            return "Invalid value for \"slot\": \(slot)"

        case let .invalidKeyType(keyType):
            return
                "Invalid value for '--algorithm': '\(keyType)' is not one of 'RSA1024', 'RSA2048', 'RSA3072', 'RSA4096', 'ECCP256', 'ECCP384', 'ED25519', 'X25519'."

        case let .invalidPinLength(len, min, max):
            return "Invalid PIN length (\(len) characters). PIN must be \(min)-\(max) characters."

        case let .invalidPukLength(len, min, max):
            return "Invalid PUK length (\(len) characters). PUK must be \(min)-\(max) characters."

        case let .invalidManagementKeyFormat(expected):
            return "Invalid value for management key: Expected \(expected)"

        case let .invalidHashAlgorithm(algorithm):
            return "Invalid hash algorithm '\(algorithm)'"

        // Authentication
        case let .pinVerificationFailed(retries):
            if let retries = retries {
                return "PIN change failed - \(retries) tries left."
            } else {
                return "PIN verification failed."
            }

        case let .pukVerificationFailed(retries):
            if let retries = retries {
                return "PUK change failed - \(retries) tries left."
            } else {
                return "PUK verification failed."
            }

        case .pinBlocked:
            return "PIN is blocked."

        case .pukBlocked:
            return "PUK is blocked."

        case .managementKeyAuthenticationFailed:
            return "Authentication with management key failed."

        // Operations
        case let .slotEmpty(slot):
            return "Slot \(slot) is empty."

        case let .slotAlreadyContains(slot, type):
            return "Slot \(slot) already contains a \(type).\n\tUse --force to overwrite."

        case let .unsupportedOperation(op, reason):
            return "Operation '\(op)' not supported: \(reason)"

        case let .certificateNotFound(slot):
            return "No certificate found in slot \(slot)."

        case let .keyGenerationFailed(slot, algorithm, reason):
            if let reason = reason {
                return "Failed to generate \(algorithm) key in slot \(slot): \(reason)"
            }
            return "Failed to generate \(algorithm) key in slot \(slot)."

        case let .importFailed(reason):
            return "Import failed: \(reason)"

        case let .exportFailed(reason):
            return "Export failed: \(reason)"

        case let .attestationNotSupported(slot):
            return "Attestation not supported for slot \(slot).\n"

        // File I/O
        case let .fileNotFound(path):
            return "File not found: \(path)"

        case let .fileReadError(path, reason):
            if let reason = reason {
                return "Failed to read file '\(path)': \(reason)"
            }
            return "Failed to read file: \(path)"

        case let .fileWriteError(path, reason):
            if let reason = reason {
                return "Failed to write file '\(path)': \(reason)"
            }
            return "Failed to write file: \(path)"

        case let .invalidFileFormat(path, expected):
            return "Invalid file format for '\(path)'.\n\tExpected: \(expected)"

        case let .generic(message):
            return message
        }
    }
}

extension Error {
    var mappedDescription: String? {
        // Check for ResponseError with specific status codes first
        if let responseError = self as? ResponseError {
            let statusHex = String(format: "0x%04X", responseError.responseStatus.rawStatus)
            return switch responseError.responseStatus.status {
            case .securityConditionNotSatisfied:
                "Authentication required (\(statusHex)). Provide --management-key or ensure management key is disabled and provide --pin."
            case .authMethodBlocked:
                "Authentication method is blocked (\(statusHex)). PIN or PUK may be locked."
            case .conditionsNotSatisfied:
                "Operation not allowed (\(statusHex)). Authentication may be required (--management-key or --pin)."
            default:
                "YubiKey responded with status \(statusHex): \(responseError.responseStatus.status)"
            }
        }

        // Check if it's a PIV.SessionError
        if let sessionError = self as? PIV.SessionError {
            switch sessionError {
            case let .invalidPin(retries):
                if retries > 0 {
                    return "Wrong PIN - \(retries) tries left."
                }
                return "Wrong PIN."
            case .pinLocked:
                return "PIN is blocked."
            case .invalidResponse:
                return "Invalid response from YubiKey."
            case .dataParseError:
                return "Failed to parse data from YubiKey."
            case .unknownKeyType:
                return "Unknown key type."
            case .authenticationFailed:
                return
                    "Authentication required. Provide --management-key or ensure management key is disabled and provide --pin."
            case .responseDataNotTLVFormatted:
                return "Response data format error."
            case .invalidKeyLength:
                return "Invalid key length."
            case .invalidDataSize:
                return "Invalid data size."
            }
        }

        // Check for SessionError
        if let sessionError = self as? SessionError {
            switch sessionError {
            case .notSupported:
                return "Operation not supported by this YubiKey."
            case .illegalArgument:
                return "Invalid argument provided."
            default:
                break
            }
        }

        // For other error types
        return nil
    }
}
