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
public enum CTAP {

    // MARK: - Commands

    enum HID {
        /// CTAPHID command codes
        enum Command: UInt8, Sendable {
            case ping = 0x01
            case msg = 0x03
            case lock = 0x04
            case `init` = 0x06
            case wink = 0x08
            case cbor = 0x10
            case cancel = 0x11
            case keepalive = 0x3b
            case error = 0x3f

            // Yubico specific commands
            case yubikeyDeviceConfig = 0x40
            case readConfig = 0x42
            case writeConfig = 0x43
        }
    }

    /// CTAP2 authenticator command codes (sent inside CTAPHID_CBOR)
    enum Command: UInt8, Sendable {
        case makeCredential = 0x01
        case getAssertion = 0x02
        case getInfo = 0x04
        case clientPIN = 0x06
        case reset = 0x07
        case getNextAssertion = 0x08
        case bioEnrollment = 0x09
        case credentialManagement = 0x0A
        case selection = 0x0B
        case largeBlobs = 0x0C
        case config = 0x0D

        // Prototype/vendor commands
        case bioEnrollmentPreview = 0x40
        case credentialManagementPreview = 0x41
    }

    // MARK: - HID Frame Structure Constants

    /// Frame type bit for initialization frames (0x80)
    static let FRAME_INIT: UInt8 = 0x80

    /// Broadcast channel ID used for INIT command (0xFFFFFFFF)
    static let CID_BROADCAST: UInt32 = 0xffff_ffff

    /// HID packet size (64 bytes for USB HID)
    static let HID_PACKET_SIZE: Int = 64

    // Initialization frame structure: CID(4) + CMD(1) + BCNT(2) + DATA(57)
    /// Size of initialization frame header: CID(4) + CMD(1) + BCNT(2)
    static let INIT_HEADER_SIZE: Int = 7
    /// Maximum payload data in an initialization frame (64 - 7 = 57 bytes)
    static let INIT_DATA_SIZE: Int = HID_PACKET_SIZE - INIT_HEADER_SIZE

    // Continuation frame structure: CID(4) + SEQ(1) + DATA(59)
    /// Size of continuation frame header: CID(4) + SEQ(1)
    static let CONT_HEADER_SIZE: Int = 5
    /// Maximum payload data in a continuation frame (64 - 5 = 59 bytes)
    static let CONT_DATA_SIZE: Int = HID_PACKET_SIZE - CONT_HEADER_SIZE

    // MARK: - Capabilities

    /// FIDO authenticator capabilities
    struct Capabilities: OptionSet, Sendable {
        let rawValue: UInt8

        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// Supports wink command (visual indicator)
        static let wink = Capabilities(rawValue: 0x01)
        /// Supports CTAP2/CBOR commands
        static let cbor = Capabilities(rawValue: 0x04)
        /// Does NOT support CTAPHID_MSG (CTAP1/U2F messages)
        static let nmsg = Capabilities(rawValue: 0x08)
    }

    // MARK: - Error Types

    /// CTAP-level errors returned from the Authenticator.
    public enum Error: Swift.Error, Sendable {
        case invalidCommand
        case invalidParameter
        case invalidLength
        case invalidSeq
        case timeout
        case channelBusy
        case lockRequired
        case invalidChannel
        case cborUnexpectedType
        case invalidCbor
        case missingParameter
        case limitExceeded
        case unsupportedExtension
        case fpDatabaseFull
        case largeBlobStorageFull
        case credentialExcluded
        case processing
        case invalidCredential
        case userActionPending
        case operationPending
        case noOperations
        case unsupportedAlgorithm
        case operationDenied
        case keyStoreFull
        case notBusy
        case noOperationPending
        case unsupportedOption
        case invalidOption
        case keepaliveCancel
        case noCredentials
        case userActionTimeout
        case notAllowed
        case pinInvalid
        case pinBlocked
        case pinAuthInvalid
        case pinAuthBlocked
        case pinNotSet
        case puatRequired
        case pinPolicyViolation
        case pinTokenExpired
        case requestTooLarge
        case actionTimeout
        case upRequired
        case uvBlocked
        case integrityFailure
        case invalidSubcommand
        case uvInvalid
        case unauthorizedPermission
        case other
        case specLast

        // Extension errors (0xE0-0xEF)
        case `extension`(UInt8)

        // Vendor errors (0xF0-0xFF)
        case vendor(UInt8)

        case unknown(UInt8)

        static func from(errorCode: UInt8) -> Error {
            switch errorCode {
            case 0x01: return .invalidCommand
            case 0x02: return .invalidParameter
            case 0x03: return .invalidLength
            case 0x04: return .invalidSeq
            case 0x05: return .timeout
            case 0x06: return .channelBusy
            case 0x0A: return .lockRequired
            case 0x0B: return .invalidChannel
            case 0x11: return .cborUnexpectedType
            case 0x12: return .invalidCbor
            case 0x14: return .missingParameter
            case 0x15: return .limitExceeded
            case 0x16: return .unsupportedExtension
            case 0x17: return .fpDatabaseFull
            case 0x18: return .largeBlobStorageFull
            case 0x19: return .credentialExcluded
            case 0x21: return .processing
            case 0x22: return .invalidCredential
            case 0x23: return .userActionPending
            case 0x24: return .operationPending
            case 0x25: return .noOperations
            case 0x26: return .unsupportedAlgorithm
            case 0x27: return .operationDenied
            case 0x28: return .keyStoreFull
            case 0x29: return .notBusy
            case 0x2A: return .noOperationPending
            case 0x2B: return .unsupportedOption
            case 0x2C: return .invalidOption
            case 0x2D: return .keepaliveCancel
            case 0x2E: return .noCredentials
            case 0x2F: return .userActionTimeout
            case 0x30: return .notAllowed
            case 0x31: return .pinInvalid
            case 0x32: return .pinBlocked
            case 0x33: return .pinAuthInvalid
            case 0x34: return .pinAuthBlocked
            case 0x35: return .pinNotSet
            case 0x36: return .puatRequired
            case 0x37: return .pinPolicyViolation
            case 0x38: return .pinTokenExpired
            case 0x39: return .requestTooLarge
            case 0x3A: return .actionTimeout
            case 0x3B: return .upRequired
            case 0x3C: return .uvBlocked
            case 0x3D: return .integrityFailure
            case 0x3E: return .invalidSubcommand
            case 0x3F: return .uvInvalid
            case 0x40: return .unauthorizedPermission
            case 0x7F: return .other
            case 0xDF: return .specLast

            // Extension errors (0xE0-0xEF)
            case 0xE0...0xEF: return .extension(errorCode)

            // Vendor errors (0xF0-0xFF)
            case 0xF0...0xFF: return .vendor(errorCode)

            // Unknown error code
            default: return .unknown(errorCode)
            }
        }
    }

    /// CTAPHID transport-layer errors returned by the authenticator via ERROR frames.
    ///
    /// These errors indicate problems at the HID transport level (as opposed to CTAP2 protocol-level errors).
    public enum HIDError: Swift.Error, Sendable {
        case invalidCmd
        case invalidPar
        case invalidLen
        case invalidSeq
        case msgTimeout
        case channelBusy
        case lockRequired
        case invalidChannel
        case other
        case unknown(UInt8)

        static func from(errorCode: UInt8) -> HIDError {
            switch errorCode {
            case 0x01:
                return .invalidCmd
            case 0x02:
                return .invalidPar
            case 0x03:
                return .invalidLen
            case 0x04:
                return .invalidSeq
            case 0x05:
                return .msgTimeout
            case 0x06:
                return .channelBusy
            case 0x0a:
                return .lockRequired
            case 0x0b:
                return .invalidChannel
            case 0x7f:
                return .other
            default:
                return .unknown(errorCode)
            }
        }
    }

    // MARK: - Command Namespaces

    /// Namespace for GetAssertion command types.
    enum GetAssertion {}

    /// Namespace for MakeCredential command types.
    enum MakeCredential {}

    /// Namespace for GetInfo command types.
    enum GetInfo {}
}
