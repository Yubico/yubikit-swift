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

/// Errors that can occur during certificate decompression.
public enum CompressionError: Error, Equatable {
    /// The data format is not recognized (neither gzip nor GIDS).
    case unsupportedFormat
    /// Decompression failed with the given reason.
    case decompressFailed(String)
}

extension Data {

    /// Decompress certificate data using the appropriate method based on header bytes.
    ///
    /// - Gzip (0x1f 0x8b magic): Uses standard gzip decompression
    /// - GIDS version 1.0 (0x01 0x00): Uses zlib decompression (Microsoft GIDS smart cards)
    ///
    /// - Returns: Decompressed certificate data.
    /// - Throws: `CompressionError` if format is unknown or decompression fails.
    func decompressCertificate() throws(CompressionError) -> Data {
        if self.isGzipped {
            do {
                return try self.gunzipped()
            } catch {
                throw .decompressFailed("gzip: \(error.message)")
            }
        } else if self.isGidsCompressed {
            do {
                return try self.gidsInflated()
            } catch {
                throw .decompressFailed("zlib: \(error.message)")
            }
        } else {
            throw .unsupportedFormat
        }
    }
}
