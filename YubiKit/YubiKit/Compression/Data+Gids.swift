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
import zlib

// MARK: - GIDS Certificate Decompression
//
// Certificate compression format from Microsoft's Generic Identity Device
// Specification (GIDS). Also used by some third-party PIV middleware.
//
// Format (from OpenSC card-gids.c):
//   Byte 0:    0x01 - compression version
//   Byte 1:    0x00 - sub-version
//   Bytes 2-3: uncompressed size (little-endian 16-bit)
//   Bytes 4+:  zlib compressed certificate
//
// See: https://github.com/OpenSC/OpenSC/blob/master/src/libopensc/card-gids.c

extension Data {

    /// Whether the receiver uses GIDS compression version 1.0.
    ///
    /// Validates:
    /// - Version bytes (0x01 0x00)
    /// - Valid zlib header (deflate compression, no preset dictionary, valid checksum)
    var isGidsCompressed: Bool {
        guard self.count > 5 else { return false }
        // GIDS compression version 1.0
        guard self[0] == 0x01 && self[1] == 0x00 else { return false }
        // Valid zlib CMF byte (compression method must be deflate = 8)
        guard self[4] & 0x0F == 8 else { return false }
        // Reject if FDICT bit is set (we don't support preset dictionaries)
        guard self[5] & 0x20 == 0 else { return false }
        // Valid zlib header checksum: (CMF * 256 + FLG) % 31 == 0
        let cmf = UInt16(self[4])
        let flg = UInt16(self[5])
        return (cmf * 256 + flg) % 31 == 0
    }

    /// Decompress a GIDS compressed certificate.
    ///
    /// Format: `[0x01] [0x00] [size_lo] [size_hi] [zlib_data...]`
    ///
    /// - Returns: Decompressed certificate data.
    /// - Throws: `GzipError` if decompression fails or length validation fails.
    func gidsInflated() throws(GzipError) -> Data {
        guard self.count > 4 else {
            throw GzipError(code: Z_DATA_ERROR, msg: nil)
        }

        // Read expected length (little-endian 16-bit, matching OpenSC)
        let expectedLength = Int(self[2]) | (Int(self[3]) << 8)

        // Decompress the zlib payload (bytes 4+)
        let payload = self.dropFirst(4)
        let decompressed = try Data(payload).gunzipped()

        // Validate decompressed length (as OpenSC does)
        guard decompressed.count == expectedLength else {
            throw GzipError(code: Z_DATA_ERROR, msg: nil)
        }

        return decompressed
    }
}
