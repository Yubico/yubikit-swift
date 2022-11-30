//
//  Array+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-11-23.
//

extension Array {
    func tuples() -> [(Element, Element)]? {
        if self.count % 2 == 0 {
            return stride(from: 0, to: count, by: 2).map {
                return (self[$0], self[$0.advanced(by: 1)])
            }
        } else {
            return nil
        }
    }
}
