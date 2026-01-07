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

import CommonCrypto
import Foundation

extension Data {

    internal func aescmac(key: Data) throws(CryptoError) -> Data {

        let constZero = Data([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        let constRb = Data([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
        ])
        let blockSize = 16
        let algorithm = CCAlgorithm(kCCAlgorithmAES128)
        let iv = Data(constZero)

        let l = try constZero.encrypt(algorithm: algorithm, key: key, iv: iv)
        var subKey1 = l.shiftedLeftByOne()
        if (l.bytes[0] & 0x80) != 0 {
            subKey1 = constRb.xor(with: subKey1)
        }
        var subKey2 = subKey1.shiftedLeftByOne()
        if (subKey1.bytes[0] & 0x80) != 0 {
            subKey2 = constRb.xor(with: subKey2)
        }

        let lastBlockIsComplete = self.count % blockSize == 0 && self.count > 0

        let paddedData: Data
        var lastIv: Data
        if lastBlockIsComplete {
            lastIv = subKey1
            paddedData = self
        } else {
            lastIv = subKey2
            paddedData = self.bitPadded()
        }
        let messageSkippingLastBlock = paddedData.subdata(in: 0..<(paddedData.count - blockSize))
        let lastBlock = paddedData.subdata(in: messageSkippingLastBlock.count..<paddedData.count)

        if messageSkippingLastBlock.count != 0 {
            // CBC encrypt the message (minus the last block) with a zero IV, and keep only the last block:
            let encryptedBlock = try messageSkippingLastBlock.encrypt(algorithm: algorithm, key: key, iv: iv).subdata(
                in: (messageSkippingLastBlock.count - blockSize)..<messageSkippingLastBlock.count
            )
            lastIv = lastIv.xor(with: encryptedBlock)
        }

        return try lastBlock.encrypt(algorithm: algorithm, key: key, iv: lastIv)
    }

    internal func bitPadded() -> Data {
        let blockSize = 16
        var paddedData = self
        paddedData.append(0x80)
        let remainder = self.count % blockSize
        let zeroPadding = remainder == 0 ? blockSize - 1 : blockSize - 1 - remainder
        return paddedData + Data(count: zeroPadding)
    }

    internal func encrypt(algorithm: CCAlgorithm, key: Data, iv: Data? = nil) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try cryptOperation(UInt32(kCCEncrypt), algorithm: algorithm, mode: mode, key: key, iv: iv)
    }

    internal func decrypt(algorithm: CCAlgorithm, key: Data, iv: Data? = nil) throws(CryptoError) -> Data {
        let mode = iv == nil ? CCMode(kCCModeECB) : CCMode(kCCModeCBC)
        return try cryptOperation(UInt32(kCCDecrypt), algorithm: algorithm, mode: mode, key: key, iv: iv)
    }

    internal func cryptOperation(
        _ operation: CCOperation,
        algorithm: CCAlgorithm,
        mode: CCMode,
        key: Data,
        iv: Data?
    ) throws(CryptoError) -> Data {
        guard !key.isEmpty else { throw CryptoError.missingData }

        let blockSize: Int
        switch Int(algorithm) {
        case kCCAlgorithm3DES:
            blockSize = kCCBlockSize3DES
        case kCCAlgorithmAES:
            blockSize = kCCBlockSizeAES128
        default:
            throw CryptoError.unsupportedAlgorithm
        }

        var outLength: Int = 0
        let bufferLength = self.count + blockSize
        var buffer = Data(count: bufferLength)
        let iv = iv ?? Data()

        let cryptorStatus: CCCryptorStatus = buffer.withUnsafeMutableBytes { bufferBytes in
            self.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        var cryptorRef: CCCryptorRef?
                        CCCryptorCreateWithMode(
                            operation,
                            mode,
                            algorithm,
                            CCPadding(ccNoPadding),
                            iv.count > 0 ? ivBytes.baseAddress : nil,
                            keyBytes.baseAddress,
                            key.count,
                            nil,
                            0,
                            0,
                            0,
                            &cryptorRef
                        )
                        return CCCryptorUpdate(
                            cryptorRef,
                            dataBytes.baseAddress,
                            self.count,
                            bufferBytes.baseAddress,
                            bufferLength,
                            &outLength
                        )
                    }
                }
            }
        }

        guard cryptorStatus == kCCSuccess else { throw CryptoError.cryptorError(cryptorStatus) }
        return buffer.subdata(in: 0..<outLength)
    }
}
