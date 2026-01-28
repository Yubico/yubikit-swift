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

// MARK: - Zlib Certificate Decompression (Net iD)
//
// Pointsharp Net iD uses a zlib-based compression format for PIV certificates:
// - Magic: 0x01 0x00
// - Length: 2 bytes (little-endian, decompressed size)
// - Data: zlib compressed certificate
//
// See: https://github.com/Yubico/yubikey-manager/pull/709

extension Data {

    /// Whether the receiver uses Net iD zlib compression (0x01 0x00 magic).
    var isNetId: Bool {
        self.starts(with: [0x01, 0x00])
    }

    /// Decompress a Net iD zlib compressed certificate.
    ///
    /// Format: [0x01 0x00] [length LE] [zlib]
    ///
    /// - Returns: Decompressed certificate data.
    /// - Throws: `GzipError` if decompression fails or length validation fails.
    func netIdInflated() throws(GzipError) -> Data {
        guard self.count > 4 else {
            throw GzipError(code: -3, msg: nil)  // Z_DATA_ERROR
        }

        // Read expected length (little-endian)
        let expectedLength = Int(self[2]) | (Int(self[3]) << 8)

        // Decompress the zlib payload (bytes 4+)
        let payload = self.dropFirst(4)
        let decompressed = try Data(payload).gunzipped()

        // Validate decompressed length
        guard decompressed.count == expectedLength else {
            throw GzipError(code: -3, msg: nil)  // Z_DATA_ERROR
        }

        return decompressed
    }
}
