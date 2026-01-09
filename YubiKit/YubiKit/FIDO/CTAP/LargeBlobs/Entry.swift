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

import CryptoKit
import Foundation

// MARK: - Entry

extension CTAP2.LargeBlobs {
    struct Entry: Sendable, Equatable {
        let ciphertext: Data
        let nonce: Data
        let origSize: Int
    }
}

// MARK: - Encrypt / Decrypt

extension CTAP2.LargeBlobs.Entry {

    init(encrypting data: Data, key: Data) throws(CTAP2.SessionError) {
        guard key.count == Self.keyLength else {
            throw .illegalArgument("largeBlobKey must be 32 bytes", source: .here())
        }

        let originalSize = data.count
        let compressed = try Self.compress(data)

        var nonce = Data(count: Self.nonceLength)
        let status = nonce.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, Self.nonceLength, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw .dataProcessingError("Failed to generate random nonce", source: .here())
        }

        do {
            let symmetricKey = SymmetricKey(data: key)
            let gcmNonce = try AES.GCM.Nonce(data: nonce)
            let ad = Self.associatedData(originalSize: originalSize)
            let sealedBox = try AES.GCM.seal(compressed, using: symmetricKey, nonce: gcmNonce, authenticating: ad)

            guard let ciphertext = sealedBox.combined?.dropFirst(Self.nonceLength) else {
                throw CTAP2.SessionError.dataProcessingError("AES-GCM encryption failed", source: .here())
            }

            self.ciphertext = Data(ciphertext)
            self.nonce = nonce
            self.origSize = originalSize
        } catch let error as CTAP2.SessionError {
            throw error
        } catch {
            throw .dataProcessingError("AES-GCM encryption failed: \(error)", source: .here())
        }
    }

    func decrypt(key: Data) throws(CTAP2.SessionError) -> Data {
        guard key.count == Self.keyLength else {
            throw .illegalArgument("largeBlobKey must be 32 bytes", source: .here())
        }
        guard nonce.count == Self.nonceLength else {
            throw .dataProcessingError("Invalid nonce length", source: .here())
        }

        let compressed: Data
        do {
            let symmetricKey = SymmetricKey(data: key)
            let combined = nonce + ciphertext
            let sealedBox = try AES.GCM.SealedBox(combined: combined)
            let ad = Self.associatedData(originalSize: origSize)
            compressed = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: ad)
        } catch {
            throw .dataProcessingError("AES-GCM decryption failed: \(error)", source: .here())
        }

        return try Self.decompress(compressed, originalSize: origSize)
    }
}

// MARK: - Private

extension CTAP2.LargeBlobs.Entry {

    private static let keyLength = 32
    private static let nonceLength = 12

    private static func associatedData(originalSize: Int) -> Data {
        var ad = Data("blob".utf8)
        var sizeLE = UInt64(originalSize).littleEndian
        ad.append(Data(bytes: &sizeLE, count: 8))
        return ad
    }

    private static func compress(_ data: Data) throws(CTAP2.SessionError) -> Data {
        guard !data.isEmpty else {
            return Data()
        }
        do {
            return try data.deflated()
        } catch {
            throw .compressionError(error, source: .here())
        }
    }

    private static func decompress(_ data: Data, originalSize: Int) throws(CTAP2.SessionError) -> Data {
        guard originalSize > 0 else {
            return Data()
        }
        guard !data.isEmpty else {
            throw .dataProcessingError("Cannot decompress empty data", source: .here())
        }
        do {
            let decompressed = try data.inflated()
            guard decompressed.count == originalSize else {
                throw CTAP2.SessionError.dataProcessingError(
                    "DEFLATE decompression size mismatch: expected \(originalSize), got \(decompressed.count)",
                    source: .here()
                )
            }
            return decompressed
        } catch let error as CTAP2.SessionError {
            throw error
        } catch {
            throw .compressionError(error, source: .here())
        }
    }
}
