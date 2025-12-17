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
public enum CTAP2 {

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
        case clientPin = 0x06
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

    /// CTAP protocol-level errors returned by the authenticator.
    ///
    /// These error codes are defined in the CTAP specification and indicate
    /// specific failure conditions during authenticator operations.
    ///
    /// - SeeAlso: [CTAP 2.2 Status Codes](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#error-responses)
    public enum Error: Swift.Error, Sendable {
        /// The command is not a valid CTAP command.
        case invalidCommand
        /// The command included an invalid parameter.
        case invalidParameter
        /// Invalid message or item length.
        case invalidLength
        /// Invalid message sequencing.
        case invalidSeq
        /// Message timed out.
        case timeout
        /// Channel busy; client should retry after a short delay.
        case channelBusy
        /// Command requires channel lock.
        case lockRequired
        /// Command not allowed on this channel ID.
        case invalidChannel
        /// Invalid/unexpected CBOR error.
        case cborUnexpectedType
        /// Error when parsing CBOR.
        case invalidCbor
        /// Missing non-optional parameter.
        case missingParameter
        /// Limit for number of items exceeded.
        case limitExceeded
        /// The requested extension is not supported.
        case unsupportedExtension
        /// Fingerprint database is full, e.g., during enrollment.
        case fpDatabaseFull
        /// Large blob storage is full.
        case largeBlobStorageFull
        /// Valid credential found in the exclude list.
        case credentialExcluded
        /// Processing; lengthy operation is in progress.
        case processing
        /// Credential not valid for the authenticator.
        case invalidCredential
        /// Authentication is waiting for user interaction.
        case userActionPending
        /// Processing; lengthy operation is in progress.
        case operationPending
        /// No request is pending.
        case noOperations
        /// Authenticator does not support requested algorithm.
        case unsupportedAlgorithm
        /// Not authorized for requested operation.
        case operationDenied
        /// Internal key storage is full.
        case keyStoreFull
        /// Authenticator is not currently busy.
        case notBusy
        /// No operation is pending.
        case noOperationPending
        /// Unsupported option.
        case unsupportedOption
        /// Not a valid option for current operation.
        case invalidOption
        /// Pending keep alive was cancelled.
        case keepaliveCancel
        /// No valid credentials provided.
        case noCredentials
        /// User action timeout occurred.
        case userActionTimeout
        /// Continuation command not allowed.
        case notAllowed
        /// PIN invalid.
        case pinInvalid
        /// PIN blocked.
        case pinBlocked
        /// PIN authentication (pinUvAuthParam) verification failed.
        case pinAuthInvalid
        /// PIN authentication blocked; requires power cycle to reset.
        case pinAuthBlocked
        /// No PIN has been set.
        case pinNotSet
        /// A pinUvAuthToken is required for the selected operation.
        case puatRequired
        /// PIN policy violation; e.g., minimum length or complexity.
        case pinPolicyViolation
        /// PIN token expired.
        case pinTokenExpired
        /// Authenticator cannot handle this request due to memory constraints.
        case requestTooLarge
        /// The current operation has timed out.
        case actionTimeout
        /// User presence is required for the requested operation.
        case upRequired
        /// Built-in user verification is disabled.
        case uvBlocked
        /// A checksum did not match.
        case integrityFailure
        /// The requested subcommand is either invalid or not implemented.
        case invalidSubcommand
        /// Built-in user verification unsuccessful; platform should retry.
        case uvInvalid
        /// The permissions parameter contains an unauthorized permission.
        case unauthorizedPermission
        /// Other unspecified error.
        case other
        /// CTAP 2 spec last error.
        case specLast

        /// Extension-specific error.
        case `extension`(UInt8)

        /// Vendor-specific error.
        case vendor(UInt8)

        /// Unknown error code.
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
    ///
    /// - SeeAlso: [CTAP 2.2 CTAPHID_ERROR](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#usb-hid-error)
    public enum HIDError: Swift.Error, Sendable {
        /// The command in the request is invalid.
        case invalidCmd
        /// The parameter(s) in the request is invalid.
        case invalidPar
        /// The length field (BCNT) is invalid for the request.
        case invalidLen
        /// The sequence does not match expected value.
        case invalidSeq
        /// The message has timed out.
        case msgTimeout
        /// The device is busy for the requesting channel.
        case channelBusy
        /// Command requires channel lock.
        case lockRequired
        /// Channel ID is not valid.
        case invalidChannel
        /// Unspecified error.
        case other
        /// Unknown error code.
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
    public enum GetAssertion {}

    /// Namespace for MakeCredential command types.
    public enum MakeCredential {}

    /// Namespace for GetInfo command types.
    public enum GetInfo {}

    /// Namespace for ClientPin command types.
    public enum ClientPin {}

    /// Namespace for CTAP2 extension types.
    public enum Extension {}
}
