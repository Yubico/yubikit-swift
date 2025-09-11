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

/// CTAP (Client to Authenticator Protocol) constants and structures
/* public */ enum CTAP {

    // CTAP Commands
    static let CMD_PING: UInt8 = 0x01
    static let CMD_MSG: UInt8 = 0x03
    static let CMD_LOCK: UInt8 = 0x04
    static let CMD_INIT: UInt8 = 0x06
    static let CMD_WINK: UInt8 = 0x08
    static let CMD_CBOR: UInt8 = 0x10
    static let CMD_CANCEL: UInt8 = 0x11
    static let CMD_KEEPALIVE: UInt8 = 0x3b
    static let CMD_ERROR: UInt8 = 0x3f

    // Frame types
    static let FRAME_INIT: UInt8 = 0x80

    // Channel IDs
    static let CID_BROADCAST: UInt32 = 0xffff_ffff

    // Frame structure constants
    static let INIT_HEADER_LEN: Int = 7  // CID(4) + CMD(1) + BCNT(2)
    static let CONT_HEADER_LEN: Int = 5  // CID(4) + SEQ(1)

    // Capabilities
    static let FIDO_CAP_WINK: UInt8 = 0x01
    static let FIDO_CAP_CBOR: UInt8 = 0x04
    static let FIDO_CAP_NMSG: UInt8 = 0x08

    // HID Error codes
    static let HID_ERR_INVALID_CMD: UInt8 = 0x01
    static let HID_ERR_INVALID_PAR: UInt8 = 0x02
    static let HID_ERR_INVALID_LEN: UInt8 = 0x03
    static let HID_ERR_INVALID_SEQ: UInt8 = 0x04
    static let HID_ERR_MSG_TIMEOUT: UInt8 = 0x05
    static let HID_ERR_CHANNEL_BUSY: UInt8 = 0x06
    static let HID_ERR_LOCK_REQUIRED: UInt8 = 0x0a
    static let HID_ERR_INVALID_CHANNEL: UInt8 = 0x0b
    static let HID_ERR_OTHER: UInt8 = 0x7f

    // CTAP2 Error codes
    static let ERR_SUCCESS: UInt8 = 0x00
    static let ERR_INVALID_COMMAND: UInt8 = 0x01
    static let ERR_INVALID_PARAMETER: UInt8 = 0x02
    static let ERR_INVALID_LENGTH: UInt8 = 0x03
    static let ERR_INVALID_SEQ: UInt8 = 0x04
    static let ERR_TIMEOUT: UInt8 = 0x05
    static let ERR_CHANNEL_BUSY: UInt8 = 0x06
    static let ERR_LOCK_REQUIRED: UInt8 = 0x0A
    static let ERR_INVALID_CHANNEL: UInt8 = 0x0B
    static let ERR_CBOR_UNEXPECTED_TYPE: UInt8 = 0x11
    static let ERR_INVALID_CBOR: UInt8 = 0x12
    static let ERR_MISSING_PARAMETER: UInt8 = 0x14
    static let ERR_LIMIT_EXCEEDED: UInt8 = 0x15
    static let ERR_UNSUPPORTED_EXTENSION: UInt8 = 0x16
    static let ERR_FP_DATABASE_FULL: UInt8 = 0x17
    static let ERR_LARGE_BLOB_STORAGE_FULL: UInt8 = 0x18
    static let ERR_CREDENTIAL_EXCLUDED: UInt8 = 0x19
    static let ERR_PROCESSING: UInt8 = 0x21
    static let ERR_INVALID_CREDENTIAL: UInt8 = 0x22
    static let ERR_USER_ACTION_PENDING: UInt8 = 0x23
    static let ERR_OPERATION_PENDING: UInt8 = 0x24
    static let ERR_NO_OPERATIONS: UInt8 = 0x25
    static let ERR_UNSUPPORTED_ALGORITHM: UInt8 = 0x26
    static let ERR_OPERATION_DENIED: UInt8 = 0x27
    static let ERR_KEY_STORE_FULL: UInt8 = 0x28
    static let ERR_NOT_BUSY: UInt8 = 0x29
    static let ERR_NO_OPERATION_PENDING: UInt8 = 0x2A
    static let ERR_UNSUPPORTED_OPTION: UInt8 = 0x2B
    static let ERR_INVALID_OPTION: UInt8 = 0x2C
    static let ERR_KEEPALIVE_CANCEL: UInt8 = 0x2D
    static let ERR_NO_CREDENTIALS: UInt8 = 0x2E
    static let ERR_USER_ACTION_TIMEOUT: UInt8 = 0x2F
    static let ERR_NOT_ALLOWED: UInt8 = 0x30
    static let ERR_PIN_INVALID: UInt8 = 0x31
    static let ERR_PIN_BLOCKED: UInt8 = 0x32
    static let ERR_PIN_AUTH_INVALID: UInt8 = 0x33
    static let ERR_PIN_AUTH_BLOCKED: UInt8 = 0x34
    static let ERR_PIN_NOT_SET: UInt8 = 0x35
    static let ERR_PUAT_REQUIRED: UInt8 = 0x36  // CTAP2.1 naming (was PIN_REQUIRED)
    static let ERR_PIN_POLICY_VIOLATION: UInt8 = 0x37
    static let ERR_PIN_TOKEN_EXPIRED: UInt8 = 0x38
    static let ERR_REQUEST_TOO_LARGE: UInt8 = 0x39
    static let ERR_ACTION_TIMEOUT: UInt8 = 0x3A
    static let ERR_UP_REQUIRED: UInt8 = 0x3B
    static let ERR_UV_BLOCKED: UInt8 = 0x3C
    static let ERR_INTEGRITY_FAILURE: UInt8 = 0x3D
    static let ERR_INVALID_SUBCOMMAND: UInt8 = 0x3E
    static let ERR_UV_INVALID: UInt8 = 0x3F
    static let ERR_UNAUTHORIZED_PERMISSION: UInt8 = 0x40
    static let ERR_OTHER: UInt8 = 0x7F
    static let ERR_SPEC_LAST: UInt8 = 0xDF
    static let ERR_EXTENSION_FIRST: UInt8 = 0xE0
    static let ERR_EXTENSION_LAST: UInt8 = 0xEF
    static let ERR_VENDOR_FIRST: UInt8 = 0xF0
    static let ERR_VENDOR_LAST: UInt8 = 0xFF

    // MARK: - Error Types

    /// CTAP-level errors returned from the Authenticator.
    /* public */ enum Error: UInt8, Swift.Error, Sendable {
        case success = 0x00
        case invalidCommand = 0x01
        case invalidParameter = 0x02
        case invalidLength = 0x03
        case invalidSeq = 0x04
        case timeout = 0x05
        case channelBusy = 0x06
        case lockRequired = 0x0A
        case invalidChannel = 0x0B
        case cborUnexpectedType = 0x11
        case invalidCbor = 0x12
        case missingParameter = 0x14
        case limitExceeded = 0x15
        case unsupportedExtension = 0x16
        case fpDatabaseFull = 0x17
        case largeBlobStorageFull = 0x18
        case credentialExcluded = 0x19
        case processing = 0x21
        case invalidCredential = 0x22
        case userActionPending = 0x23
        case operationPending = 0x24
        case noOperations = 0x25
        case unsupportedAlgorithm = 0x26
        case operationDenied = 0x27
        case keyStoreFull = 0x28
        case notBusy = 0x29
        case noOperationPending = 0x2A
        case unsupportedOption = 0x2B
        case invalidOption = 0x2C
        case keepaliveCancel = 0x2D
        case noCredentials = 0x2E
        case userActionTimeout = 0x2F
        case notAllowed = 0x30
        case pinInvalid = 0x31
        case pinBlocked = 0x32
        case pinAuthInvalid = 0x33
        case pinAuthBlocked = 0x34
        case pinNotSet = 0x35
        case puatRequired = 0x36
        case pinPolicyViolation = 0x37
        case pinTokenExpired = 0x38
        case requestTooLarge = 0x39
        case actionTimeout = 0x3A
        case upRequired = 0x3B
        case uvBlocked = 0x3C
        case integrityFailure = 0x3D
        case invalidSubcommand = 0x3E
        case uvInvalid = 0x3F
        case unauthorizedPermission = 0x40
        case other = 0x7F
        case specLast = 0xDF

        // Extension errors (0xE0-0xEF)
        case extension0 = 0xE0
        case extension1 = 0xE1
        case extension2 = 0xE2
        case extension3 = 0xE3
        case extension4 = 0xE4
        case extension5 = 0xE5
        case extension6 = 0xE6
        case extension7 = 0xE7
        case extension8 = 0xE8
        case extension9 = 0xE9
        case extensionA = 0xEA
        case extensionB = 0xEB
        case extensionC = 0xEC
        case extensionD = 0xED
        case extensionE = 0xEE
        case extensionF = 0xEF

        // Vendor errors (0xF0-0xFF)
        case vendor0 = 0xF0
        case vendor1 = 0xF1
        case vendor2 = 0xF2
        case vendor3 = 0xF3
        case vendor4 = 0xF4
        case vendor5 = 0xF5
        case vendor6 = 0xF6
        case vendor7 = 0xF7
        case vendor8 = 0xF8
        case vendor9 = 0xF9
        case vendorA = 0xFA
        case vendorB = 0xFB
        case vendorC = 0xFC
        case vendorD = 0xFD
        case vendorE = 0xFE
        case vendorF = 0xFF

        /* public */ var localizedDescription: String {
            String(format: "CTAP error: 0x%02x", rawValue)
        }
    }

    /// Unknown CTAP error codes
    /* public */ struct UnknownError: Swift.Error, Sendable {
        /* public */ let errorCode: UInt8

        /* public */ init(errorCode: UInt8) {
            self.errorCode = errorCode
        }

        /* public */ var localizedDescription: String {
            "Unknown CTAP error code: 0x\(String(format: "%02x", errorCode))"
        }
    }

    /// HID transport errors
    /* public */ enum HIDError: Swift.Error, Sendable {
        // HID errors with codes
        case invalidCmd(UInt8)
        case invalidPar
        case invalidLen
        case invalidSeq
        case msgTimeout
        case channelBusy
        case lockRequired
        case invalidChannel
        case other

        // Transport errors
        case parseError(String)
        case framingError(String)
        case unexpectedResponse(expected: UInt8, received: UInt8)

        static func from(errorCode: UInt8) -> HIDError? {
            switch errorCode {
            case HID_ERR_INVALID_CMD:
                return .invalidCmd(errorCode)
            case HID_ERR_INVALID_PAR:
                return .invalidPar
            case HID_ERR_INVALID_LEN:
                return .invalidLen
            case HID_ERR_INVALID_SEQ:
                return .invalidSeq
            case HID_ERR_MSG_TIMEOUT:
                return .msgTimeout
            case HID_ERR_CHANNEL_BUSY:
                return .channelBusy
            case HID_ERR_LOCK_REQUIRED:
                return .lockRequired
            case HID_ERR_INVALID_CHANNEL:
                return .invalidChannel
            case HID_ERR_OTHER:
                return .other
            default:
                return nil
            }
        }
    }
}
