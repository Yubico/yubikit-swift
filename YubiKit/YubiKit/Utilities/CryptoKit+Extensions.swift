//
//  CryptoKit+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-11-23.
//

import Foundation
import CryptoKit

extension CryptoKit.Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }

    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}
