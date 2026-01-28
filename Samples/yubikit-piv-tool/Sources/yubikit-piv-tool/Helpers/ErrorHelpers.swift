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

// MARK: - Error Helpers

/// Print error message and exit immediately
func exitWithError(_ message: String) -> Never {
    fputs("Error: \(message)\n", stderr)
    Foundation.exit(EXIT_FAILURE)
}

/// Handle SmartCardConnectionError and exit immediately
func handleConnectionError(_ error: SmartCardConnectionError) -> Never {
    let message =
        switch error {
        case .busy:
            "Another connection is already active."
        case .unsupported:
            "Smart card functionality is not supported on this device."
        case .cancelled:
            "Connection was cancelled."
        case .cancelledByUser:
            "Connection was cancelled by user."
        case .connectionLost:
            "Connection to YubiKey was lost."
        case .noDevicesFound:
            "No YubiKey devices found."
        case .pollingFailed:
            "Failed to poll for YubiKey."
        case .setupFailed:
            "Failed to setup connection."
        case .transmitFailed:
            "Failed to communicate with YubiKey."
        case .malformedData:
            "Invalid data format."
        }
    exitWithError(message)
}

/// Handle PIVSessionError with context and exit immediately
func handlePIVError(_ error: PIVSessionError, context: String = "PIN") -> Never {
    let message: String
    switch error {
    case let .failedResponse(responseStatus, _):
        let statusHex = String(format: "0x%04X", responseStatus.rawStatus)
        switch responseStatus.status {
        case .securityConditionNotSatisfied:
            message =
                "Authentication required (\(statusHex)). Provide --management-key or ensure management key is disabled and provide --pin."
        case .authMethodBlocked:
            message = "Authentication method is blocked (\(statusHex)). PIN or PUK may be locked."
        case .conditionsNotSatisfied:
            message =
                "Operation not allowed (\(statusHex)). Authentication may be required (--management-key or --pin)."
        default:
            message = "YubiKey responded with status \(statusHex): \(responseStatus.status)"
        }
    case let .invalidPin(retries, _):
        if retries > 0 {
            message = "\(context) verification failed - \(retries) tries left."
        } else {
            message = "\(context) verification failed."
        }
    case .pinLocked:
        message = "\(context) is blocked."
    case .responseParseError(let parseMessage, _):
        message = "Failed to parse response from YubiKey: \(parseMessage)"
    case .unknownKeyType(let rawValue, _):
        message = "Unknown key type: \(rawValue)"
    case .authenticationFailed:
        message =
            "Authentication required. Provide --management-key or ensure management key is disabled and provide --pin."
    case .invalidKeyLength:
        message = "Invalid key length."
    case .invalidDataSize:
        message = "Invalid data size."
    case .featureNotSupported:
        message = "Operation not supported by this YubiKey."
    case .illegalArgument(let argMessage, _):
        message = "Invalid argument: \(argMessage)"
    case .connectionError(let connectionError, _):
        message = "Connection error: \(connectionError.localizedDescription)"
    case .scpError(let scpError, _):
        message = "Secure channel error: \(scpError.localizedDescription)"
    case .cryptoError(let encMessage, let error, _):
        if let error = error {
            message = "Encryption failed: \(encMessage) (\(error.localizedDescription))"
        } else {
            message = "Encryption failed: \(encMessage)"
        }
    case .dataProcessingError(let dataMessage, _):
        message = "Data processing error: \(dataMessage)"
    case .compression(let error, _):
        message = "Compression error: \(error.localizedDescription)"
    case .other(let error, _):
        message = "Error: \(error.localizedDescription)"
    }
    exitWithError(message)
}
