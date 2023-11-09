//
//  String+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2023-11-09.
//

import Foundation

extension String: Error, LocalizedError {
    public var errorDescription: String? { self }
}
