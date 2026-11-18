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
import YubiKit

enum ParameterValidator {
    static func validateSlot(_ slot: String) throws -> PIV.Slot {
        // Trim whitespace and validate empty string
        let trimmedSlot = slot.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let pivSlot = PIV.Slot(fromString: trimmedSlot) else {
            throw ToolError("Invalid slot: \(slot)")
        }

        return pivSlot
    }

    static func validateManagementKey(_ hexString: String) throws -> Data {
        let trimmedHex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard [32, 48, 64].contains(trimmedHex.count),
            trimmedHex.allSatisfy({ $0.isASCII && $0.isHexDigit }),
            let data = Data(hexString: trimmedHex), data.count * 2 == trimmedHex.count
        else {
            throw ToolError("Invalid management key format.\n\tExpected: 32, 48 or 64 hex characters for AES or 3DES")
        }
        return data
    }

    static func validateKeyType(_ value: String) throws -> PIV.KeyType {
        switch value.uppercased().replacingOccurrences(of: "-", with: "") {
        case "RSA1024": .rsa(.bits1024)
        case "RSA2048": .rsa(.bits2048)
        case "RSA3072": .rsa(.bits3072)
        case "RSA4096": .rsa(.bits4096)
        case "ECCP256", "P256": .ec(.secp256r1)
        case "ECCP384", "P384": .ec(.secp384r1)
        case "ED25519": .ed25519
        case "X25519": .x25519
        case "MLDSA44": .mlDSA(.mlDSA44)
        case "MLDSA65": .mlDSA(.mlDSA65)
        case "MLDSA87": .mlDSA(.mlDSA87)
        case "MLKEM512": .mlKEM(.mlKEM512)
        case "MLKEM768": .mlKEM(.mlKEM768)
        case "MLKEM1024": .mlKEM(.mlKEM1024)
        default: throw ToolError("Invalid key type: \(value)")
        }
    }

    static func validateHashAlgorithm(_ algorithm: String) throws -> PIV.HashAlgorithm {
        // Trim whitespace and validate empty string
        let algorithm = algorithm.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !algorithm.isEmpty else {
            throw ToolError("Invalid hash algorithm: \(algorithm)")
        }

        switch algorithm.uppercased() {
        case "SHA1": return .sha1
        case "SHA256": return .sha256
        case "SHA384": return .sha384
        case "SHA512": return .sha512
        default:
            throw ToolError("Invalid hash algorithm: \(algorithm)")
        }
    }

    // Validate PIN format and length constraints
    static func validatePin(_ pin: String) throws {
        // PIV PIN must be 6-8 characters
        guard pin.count >= 6, pin.count <= 8 else {
            throw ToolError("Invalid PIN length: \(pin.count).\n\tPIN must be 6-8 characters.")
        }

        // PIN must contain only ASCII digits
        guard pin.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw ToolError(
                "Invalid format for PIN.\n\tExpected: 6-8 numeric digits.\n\tActual: contains non-numeric characters"
            )
        }
    }

    // Validate PUK format and length constraints
    static func validatePuk(_ puk: String) throws {
        // PIV PUK must be 6-8 characters
        guard puk.count >= 6, puk.count <= 8 else {
            throw ToolError("Invalid PUK length: \(puk.count).\n\tPUK must be 6-8 characters.")
        }

        // PUK must contain only ASCII digits
        guard puk.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            throw ToolError(
                "Invalid format for PUK.\n\tExpected: 6-8 numeric digits.\n\tActual: contains non-numeric characters"
            )
        }
    }
}

// MARK: - Helper Extensions

extension Data {
    // Convert hex string to Data for PIV management key operations
    fileprivate init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        let len = hex.count / 2
        var data = Data(capacity: len)
        var index = hex.startIndex

        for _ in 0..<len {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let b = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(b)
            index = nextIndex
        }

        self = data
    }
}

extension PIV.Slot {
    // Parse PIV slot from hex string (e.g., "9a", "9c", "9d", "9e")
    // PIV slots are single bytes representing different key usage purposes
    init?(fromString string: String) {
        guard string.count == 2,  // 1 byte represented as 2 hex chars
            let asInt8 = UInt8(string.lowercased(), radix: 16)
        else {
            return nil
        }

        self.init(rawValue: asInt8)
    }
}
