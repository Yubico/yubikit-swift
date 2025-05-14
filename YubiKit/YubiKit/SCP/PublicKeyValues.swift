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

/// Holds the X and Y coordinates and curve for an EC public key
struct PublicKeyValues {
    enum Error: Swift.Error {
        case invalidKeyRepresentation(String?)
        case unsupportedKeyType

        static let invalidKeyRepresentation = Error.invalidKeyRepresentation(nil)
    }

    let curve: ECKeyCurve
    let x: Data
    let y: Data

    /// Init from raw uncompressed EC point bytes
    /// - Parameter rawRepresentation: Data starts with 0x04, followed by X and Y coordinates
    init(rawRepresentation: Data) throws {
        guard rawRepresentation.first == 0x04 else {
            throw Error.invalidKeyRepresentation
        }
        let coordLen = (rawRepresentation.count - 1) / 2
        self.curve = try ECKeyCurve(length: rawRepresentation.count)
        self.x = rawRepresentation.subdata(in: 1..<1 + coordLen)
        self.y = rawRepresentation.subdata(in: 1 + coordLen..<rawRepresentation.count)
    }

    /// The SEC1 uncompressed EC point representation.
    /// The data begins with a 0x04 prefix byte followed by the X coordinate (big‑endian) and Y coordinate (big‑endian) bytes.
    /// - Returns: A `Data` object containing the full uncompressed EC point.
    var rawRepresentation: Data {
        var result = Data([0x04])
        result.append(contentsOf: x)
        result.append(contentsOf: y)
        return result
    }

    /// Extract PublicKeyValues from a SecKey
    /// - Parameter secKey: EC public SecKey
    /// - Returns: Parsed PublicKeyValues
    static func from(secKey: SecKey) throws -> PublicKeyValues {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            let error = error?.takeRetainedValue()
            throw Error.invalidKeyRepresentation(error?.localizedDescription)
        }
        return try PublicKeyValues(rawRepresentation: data)
    }
}

/// Supported EC key curves (uncompressed point)
enum ECKeyCurve {
    case prime256v1

    /// Bit size of the curve
    private var keySize: Int {
        switch self {
        case .prime256v1: return 256
        }
    }

    /// Expected length of uncompressed EC point: 1 byte header + 2 * (keySize/8)
    private var uncompressedPointLength: Int {
        return 1 + (keySize/8) * 2
    }

    /// Initialize based on raw point length
    fileprivate init(length: Int) throws {
        if length == ECKeyCurve.prime256v1.uncompressedPointLength {
            self = .prime256v1
        } else {
            throw PublicKeyValues.Error.unsupportedKeyType
        }
    }
}
