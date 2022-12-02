//
//  NSLock+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-02.
//

import Foundation

extension NSLock {
    @discardableResult
    internal func with<T>(_ block: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try block()
    }
}
