// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation

enum StreamError: Error {
    case readError
    case writeError
    case timeout
}

private struct YubiKeyConstants {
    static let bufferSize = 512
    static let probeTime = 0.05
    static let timeout = 10.0
}

extension OutputStream {

    internal func writeToYubiKey(data: Data) throws {
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
                return self.write(buffer.baseAddress!.assumingMemoryBound(to: UInt8.self), maxLength: length)
            }
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

            guard read > 0 else { throw self.streamError ?? StreamError.readError }
            data.append(buffer, count: read)

            if self.hasBytesAvailable { Thread.sleep(forTimeInterval: YubiKeyConstants.probeTime) }
            timer += YubiKeyConstants.probeTime
            if timer > YubiKeyConstants.timeout { throw StreamError.timeout }
        }
        return data
    }
}
