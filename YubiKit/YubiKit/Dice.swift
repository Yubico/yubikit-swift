//
//  Dice.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-11.
//

import Foundation

public struct Dice {
    
    public init() {}
    
    public func roll() -> Int {
        return Int.random(in: 1...6)
    }
}
