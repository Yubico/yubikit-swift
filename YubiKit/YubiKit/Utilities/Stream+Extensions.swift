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
}

fileprivate let yubiKeyBufferSize = 512
fileprivate let yubiKeyProbeTime = 0.05

extension OutputStream {
    
    internal func writeToYubiKey(data: Data) throws {
        print("⚡️ about to write \(data.hexEncodedString)")
        
        while !self.hasSpaceAvailable {
            print("⚡️ hasSpaceAvailable \(self.hasSpaceAvailable)")
            Thread.sleep(forTimeInterval: 0.01)
        }
        
        var remaining = data[...]
        while !remaining.isEmpty {
            let bytesWritten = remaining.withUnsafeBytes { buffer in
                let length = min(remaining.count, yubiKeyBufferSize)
                print("⚡️ write chunk \(length): \(remaining.subdata(in: 0..<length).hexEncodedString)")
                return self.write(buffer.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: length)
            }
            print("⚡️ bytesWritte: \(bytesWritten)")
            guard bytesWritten > 0 else { throw self.streamError ?? StreamError.writeError }
            remaining = remaining.dropFirst(bytesWritten)
            if !remaining.isEmpty { Thread.sleep(forTimeInterval: yubiKeyProbeTime) }
        }
    }
}


extension InputStream {
    
    internal func readFromYubiKey() throws -> Data {
        var data = Data()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: yubiKeyBufferSize)
        defer {
            buffer.deallocate()
        }
        
        while !self.hasBytesAvailable {
            Thread.sleep(forTimeInterval: yubiKeyProbeTime)
        }
        while self.hasBytesAvailable {
            let read = self.read(buffer, maxLength: yubiKeyBufferSize)
            print("⚡️ read \(read) bytes")

            guard read > 0 else { throw self.streamError ?? StreamError.readError }
            data.append(buffer, count: read)
            print("⚡️ data: \(data.hexEncodedString)")

            if self.hasBytesAvailable { Thread.sleep(forTimeInterval: yubiKeyProbeTime) }
        }
        return data
    }
}
