//
//  Sequence+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-11-23.
//

public extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var values = [T]()
        for element in self {
            try await values.append(transform(element))
        }
        return values
    }
}
