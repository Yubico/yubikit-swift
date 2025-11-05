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

    /// CTAP Commands
    public enum Command: UInt8, Sendable {
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
    enum Error: UInt8, Swift.Error, Sendable {
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

        var localizedDescription: String {
            String(format: "CTAP error: 0x%02x", rawValue)
        }
    }

    /// Unknown CTAP error codes
    struct UnknownError: Swift.Error, Sendable {
        let errorCode: UInt8

        init(errorCode: UInt8) {
            self.errorCode = errorCode
        }

        var localizedDescription: String {
            "Unknown CTAP error code: 0x\(String(format: "%02x", errorCode))"
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
}
