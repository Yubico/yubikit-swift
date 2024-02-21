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
import CommonCrypto


/// Touch policy for PIV application.
public enum PIVTouchPolicy: UInt8 {
    case defaultPolicy = 0x0
    case never = 0x1
    case always = 0x2
    case cached = 0x3
}

/// Pin policy for PIV application.
public enum PIVPinPolicy: UInt8 {
    case defaultPolicy = 0x0
    case never = 0x1
    case once = 0x2
    case always = 0x3
};

public enum PIVSlot: UInt8 {
    case authentication = 0x9a
    case signature = 0x9c
    case keyManagement = 0x9d
    case cardAuth = 0x9e
    case attestation = 0xf9
    
    var objectId: Data {
        switch self {
        case .authentication:
            return Data([0x5f, 0xc1, 0x05])
        case .signature:
            return Data([0x5f, 0xc1, 0x0a])
        case .keyManagement:
            return Data([0x5f, 0xc1, 0x0b])
        case .cardAuth:
            return Data([0x5f, 0xc1, 0x01])
        case .attestation:
            return Data([0x5f, 0xff, 0x01])
        }
    }
}

public enum PIVKeyType: UInt8 {
    case RSA1024 = 0x06
    case RSA2048 = 0x07
    case ECCP256 = 0x11
    case ECCP384 = 0x14
    case unknown = 0x00
    
    public init?(_ secKey: SecKey) {
        guard let dict = SecKeyCopyAttributes(secKey) else { return nil }
        let attributes = dict as NSDictionary
        guard let size = attributes[kSecAttrKeySizeInBits] as? Int else { return nil }
        guard let type = attributes[kSecAttrKeyType] as? String else { return nil }
        let secAttrKeyTypeRSA = kSecAttrKeyTypeRSA as String
        let secAttrKeyTypeEC = kSecAttrKeyTypeEC as String
        switch type {
        case secAttrKeyTypeRSA:
            switch size {
            case 1024:
                self = .RSA1024
            case 2048:
                self = .RSA2048
            default:
                return nil
            }
        case secAttrKeyTypeEC:
            switch size {
            case 256:
                self = .ECCP256
            case 384:
                self = .ECCP384
            default:
                return nil
            }
        default:
            return nil
        }
    }
    
    var size: UInt {
        switch (self) {
        case .ECCP256:
            return 256 / 8;
        case .ECCP384:
            return 384 / 8;
        case .RSA1024:
            return 1024 / 8;
        case .RSA2048:
            return 2048 / 8;
        default:
            return 0;
        }
    }
}

public enum PIVVerifyPinResult: Equatable {
    case success(Int)
    case fail(Int)
    case pinLocked
}

public enum PIVSessionError: Error {
    case invalidCipherTextLength
    case unsupportedOperation
    case dataParseError
    case unknownKeyType
    case invalidPin
    case pinLocked
    case invalidResponse
    case authenticationFailed
    case responseDataNotTLVFormatted
    case failedCreatingCertificate
    case badKeyLength
    case invalidInput
    case unsupportedKeyType
}

public struct PIVManagementKeyMetadata {
    
    public let isDefault: Bool
    public let keyType: PIVManagementKeyType
    public let touchPolicy: PIVTouchPolicy
}

public struct PIVSlotMetadata {
    public let keyType: PIVKeyType
    public let pinPolicy: PIVPinPolicy
    public let touchPolicy: PIVTouchPolicy
    public let generated: Bool
    public let publicKey: Data
}

public struct PIVPinPukMetadata {
    public let isDefault: Bool
    public let retriesTotal: Int
    public let retriesRemaining: Int
}

public enum PIVManagementKeyType: UInt8 {
    case tripleDES = 0x03
    case AES128 = 0x08
    case AES192 = 0x0a
    case AES256 = 0x0c
    
    var keyLength: Int {
        switch self {
        case .tripleDES, .AES192:
            return 24
        case .AES128:
            return 16
        case .AES256:
            return 32
        }
    }
    
    var challengeLength: Int {
        switch self {
        case .tripleDES:
            return 8
        case .AES128, .AES192, .AES256:
            return 16
        }
    }
    
    var ccAlgorithm: UInt32 {
        switch self {
        case .tripleDES:
            return UInt32(kCCAlgorithm3DES)
        case .AES128, .AES192, .AES256:
            return UInt32(kCCAlgorithmAES)
        }
    }
}
