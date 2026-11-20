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

import Darwin
import Foundation

enum CommandIO {
    static func read(_ path: String) throws -> Data {
        if path == "-" { return try FileHandle.standardInput.readToEnd() ?? Data() }
        return try Data(contentsOf: URL(fileURLWithPath: path))
    }

    static func write(_ data: Data, to path: String, secret: Bool = false) throws {
        if path == "-" {
            try FileHandle.standardOutput.write(contentsOf: data)
        } else if secret {
            let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
            guard descriptor >= 0 else {
                let reason = String(cString: strerror(errno))
                throw ToolError("Cannot create secret output '\(path)' (must not already exist): \(reason)")
            }
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            defer { try? handle.close() }
            do {
                try handle.write(contentsOf: data)
            } catch {
                unlink(path)
                throw error
            }
        } else {
            try data.write(to: URL(fileURLWithPath: path))
        }
    }
}
