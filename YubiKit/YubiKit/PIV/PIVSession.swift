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
import Security
import OSLog

/// Touch policy for PIV application.
public enum PIVTouchPolicy: UInt {
    case `default` = 0x0
    case never = 0x1
    case always = 0x2
    case cached = 0x3
}

/// Pin policy for PIV application.
public enum PIVPinPolicy: UInt {
    case `default` = 0x0
    case never = 0x1
    case nce = 0x2
    case always = 0x3
};

public enum PIVSlot: UInt {
    case authentication = 0x9a
    case signature = 0x9c
    case keyManagement = 0x9d
    case cardAuth = 0x9e
    case attestation = 0xf9
}

public enum PIVKeyType: UInt {
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

public enum PIVError: Error {
    case invalidCipherTextLength
    case unsupportedOperation
    case dataParseError
    case unknownKeyType
    case invalidPin
    case pinLocked
    case invalidResponse
    case authenticationFailed
};

public final actor PIVSession: Session, InternalSession {
    public var version: Version
    private weak var _connection: Connection?
    internal func connection() async -> Connection? {
        return _connection
    }
    internal func setConnection(_ connection: Connection?) async {
        _connection = connection
    }
    
    private init(connection: Connection) async throws {
        try await connection.selectApplication(.piv)
        let versionApdu = APDU(cla: 0, ins: 0xfd, p1: 0, p2: 0)
        guard let version = try await Version(withData: connection.send(apdu: versionApdu)) else {
            throw PIVError.dataParseError
        }
        self.version = version
        Logger.oath.debug("\(String(describing: self).lastComponent), \(#function): \(String(describing: version))")
        self._connection = connection
        let internalConnection = await internalConnection()
        await internalConnection?.setSession(self)
    }
    
    public static func session(withConnection connection: Connection) async throws -> PIVSession {
        // Close active session if there is one
        let internalConnection = connection as! InternalConnection
        let currentSession = await internalConnection.session()
        await currentSession?.end()
        // Return new PIVSession
        return try await PIVSession(connection: connection)
    }
    
    public func end() async {
        
    }
    
    
    public func signWithKey(inSlot slot: PIVSlot, type: PIVKeyType, algorithm: SecKeyAlgorithm, message:Data) async throws -> Data {
        
        
        
        return Data()
    }

    
}
