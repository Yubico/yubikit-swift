//
//  TKTLVRecord+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-11-23.
//

import CryptoTokenKit

extension TKTLVRecord {
    static func dictionaryOfData(from data: Data) -> [TKTLVTag: Data]? {
        self.sequenceOfRecords(from: data)?.reduce(into: [TKTLVTag: Data]()) {
            $0[$1.tag] = $1.value
        }
    }
}

extension Sequence where Element == TKTLVRecord {
    func recordsAsData() -> Data {
        self.reduce(into: Data()) { partialResult, record in
            partialResult.append(record.data)
        }
    }
}
