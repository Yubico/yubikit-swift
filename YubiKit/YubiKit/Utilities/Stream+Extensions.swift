//
//  Stream+Extensions.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-13.
//

import Foundation

enum StreamError: Error {
    case readError
    case writeError
    case timeout
}

fileprivate struct YubiKeyConstants {
    static let bufferSize = 512
    static let probeTime = 0.05
    static let timeout = 10.0
}

extension OutputStream {
    
    internal func writeToYubiKey(data: Data) throws {
        print("⚡️ about to write \(data.hexEncodedString)")
        var timer = 0.0
        while !self.hasSpaceAvailable {
            Thread.sleep(forTimeInterval: YubiKeyConstants.probeTime)
            timer += YubiKeyConstants.probeTime
            if timer > YubiKeyConstants.timeout { throw StreamError.timeout }
        }
        
        var remaining = data[...]
        while !remaining.isEmpty {
            let bytesWritten = remaining.withUnsafeBytes { buffer in
                let length = min(remaining.count, YubiKeyConstants.bufferSize)
                print("⚡️ write chunk \(length): \(remaining.subdata(in: 0..<length).hexEncodedString)")
                return self.write(buffer.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: length)
            }
            print("⚡️ bytesWritte: \(bytesWritten)")
            guard bytesWritten > 0 else { throw self.streamError ?? StreamError.writeError }
            remaining = remaining.dropFirst(bytesWritten)
            if !remaining.isEmpty { Thread.sleep(forTimeInterval: YubiKeyConstants.probeTime) }
            timer += YubiKeyConstants.probeTime
            if timer > YubiKeyConstants.timeout { throw StreamError.timeout }
        }
    }
}


extension InputStream {
    
    internal func readFromYubiKey() throws -> Data {
        var data = Data()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: YubiKeyConstants.bufferSize)
        defer {
            buffer.deallocate()
        }
        
        var timer = 0.0
        while !self.hasBytesAvailable {
            Thread.sleep(forTimeInterval: YubiKeyConstants.probeTime)
            timer += YubiKeyConstants.probeTime
            if timer > YubiKeyConstants.timeout { throw StreamError.timeout }
        }
        while self.hasBytesAvailable {
            let read = self.read(buffer, maxLength: YubiKeyConstants.bufferSize)
            print("⚡️ read \(read) bytes")

            guard read > 0 else { throw self.streamError ?? StreamError.readError }
            data.append(buffer, count: read)
            print("⚡️ data: \(data.hexEncodedString)")

            if self.hasBytesAvailable { Thread.sleep(forTimeInterval: YubiKeyConstants.probeTime) }
            timer += YubiKeyConstants.probeTime
            if timer > YubiKeyConstants.timeout { throw StreamError.timeout }
        }
        return data
    }
}
