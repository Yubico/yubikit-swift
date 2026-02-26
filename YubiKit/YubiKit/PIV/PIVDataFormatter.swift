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

// Utilities for formatting data for PIV cryptographic operations
internal enum PIVDataFormatter {

    // Prepares data for RSA signing by applying the specified signature algorithm.
    // Creates a temporary RSA key pair to format the data according to the
    // specified signature algorithm, then encrypts it with raw RSA encryption.
    internal static func prepareDataForRSASigning(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSASignatureAlgorithm
    ) throws(PIVSessionError) -> Data {
        do {
            return try Crypto.RSA.prepareSignatureData(
                data,
                keySize: keySize,
                algorithm: algorithm
            )
        } catch {
            throw .cryptoError("Failed to prepare data for RSA signing", error: error, source: .here())
        }
    }

    // Prepares data for ECDSA signing by hashing or formatting the input.
    // For message signatures, hashes the input data. For digest signatures, uses data as-is.
    // The resulting hash is truncated or padded to match the key size.
    internal static func prepareDataForECDSASigning(
        _ data: Data,
        curve: EC.Curve,
        algorithm: PIV.ECDSASignatureAlgorithm
    ) -> Data {
        var hash: Data
        switch algorithm {
        case .hash(let hashAlg):
            switch hashAlg {
            case .sha1:
                hash = data.sha1()
            case .sha224:
                hash = data.sha224()
            case .sha256:
                hash = data.sha256()
            case .sha384:
                hash = data.sha384()
            case .sha512:
                hash = data.sha512()
            }
        case .prehashed:
            // For digest signatures, the data is already hashed
            hash = data
        }

        let keySize = curve.keySizeInBits / 8
        if hash.count == keySize {
            return hash
        } else if hash.count > keySize {
            return hash.subdata(in: 0..<keySize)
        } else {
            return Data(count: keySize - hash.count) + hash
        }
    }

    // Prepares data for RSA encryption by applying the specified encryption algorithm.
    // Creates a temporary RSA key pair to format the data according to the
    // specified encryption algorithm.
    internal static func prepareDataForRSAEncryption(
        _ data: Data,
        keySize: RSA.KeySize,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws(PIVSessionError) -> Data {
        do {
            return try Crypto.RSA.prepareEncryptionData(
                data,
                keySize: keySize,
                algorithm: algorithm
            )
        } catch {
            throw .cryptoError("Failed to prepare data for RSA encryption", error: error, source: .here())
        }
    }

    // Extracts the original data from RSA encryption format.
    // Reverses the RSA encryption preparation by using a temporary RSA key pair
    // to decrypt the encryption-formatted data.
    internal static func extractDataFromRSAEncryption(
        _ data: Data,
        algorithm: PIV.RSAEncryptionAlgorithm
    ) throws(PIVSessionError) -> Data {
        guard let keySize = RSA.KeySize.allCases.first(where: { $0.byteCount == data.count }) else {
            throw .invalidDataSize(source: .here())
        }

        do {
            return try Crypto.RSA.extractEncryptionData(
                data,
                keySize: keySize,
                algorithm: algorithm
            )
        } catch {
            throw .cryptoError("Failed to extract data from RSA encryption", error: error, source: .here())
        }
    }

    // Extracts the original data from RSA signature format.
    // Reverses the RSA signature preparation by using a temporary RSA key pair
    // to decrypt the signature-formatted data.
    internal static func extractDataFromRSASigning(
        _ data: Data,
        algorithm: PIV.RSASignatureAlgorithm
    ) throws(PIVSessionError) -> Data {
        guard let keySize = RSA.KeySize.allCases.first(where: { $0.byteCount == data.count }) else {
            throw .invalidDataSize(source: .here())
        }

        do {
            return try Crypto.RSA.extractSignatureData(
                data,
                keySize: keySize,
                algorithm: algorithm
            )
        } catch {
            throw .cryptoError("Failed to extract data from RSA signature", error: error, source: .here())
        }
    }
}
