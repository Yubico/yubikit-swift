//
//  File.swift
//  
//
//  Created by Jens Utbult on 2021-11-26.
//

import Foundation

func emulateSlowTask() {
    var numbers = [Int]()
    _ = (1...10_000_000).map { number in
        numbers.append(number + number)
    }
}
