//
//  File.swift
//  
//
//  Created by Jens Utbult on 2021-11-26.
//

import Foundation

func emulateSlowTask() {
    print("Start slow task on \(Thread.current)")
    var numbers = [Int]()
    _ = (1...1_000_000).map { number in
        numbers.append(number + number)
    }
    print("Finish slow task on \(Thread.current)")
}
