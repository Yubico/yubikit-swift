// The MIT License (MIT)
//
// © 2014-2023 1024jp <wolfrosch.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import zlib

import struct Foundation.Data

/// Errors on gzipping/gunzipping based on the zlib error codes.
struct GzipError: Swift.Error, Sendable {
    // cf. http://www.zlib.net/manual.html

    enum Kind: Equatable, Sendable {
        /// The stream structure was inconsistent.
        ///
        /// - underlying zlib error: `Z_STREAM_ERROR` (-2)
        case stream

        /// The input data was corrupted
        /// (input stream not conforming to the zlib format or incorrect check value).
        ///
        /// - underlying zlib error: `Z_DATA_ERROR` (-3)
        case data

        /// There was not enough memory.
        ///
        /// - underlying zlib error: `Z_MEM_ERROR` (-4)
        case memory

        /// No progress is possible or there was not enough room in the output buffer.
        ///
        /// - underlying zlib error: `Z_BUF_ERROR` (-5)
        case buffer

        /// The zlib library version is incompatible with the version assumed by the caller.
        ///
        /// - underlying zlib error: `Z_VERSION_ERROR` (-6)
        case version

        /// An unknown error occurred.
        ///
        /// - parameter code: return error by zlib
        case unknown(code: Int)
    }

    /// Error kind.
    let kind: Kind

    /// Returned message by zlib.
    let message: String

    internal init(code: Int32, msg: UnsafePointer<CChar>?) {

        self.message = msg.flatMap(String.init(validatingCString:)) ?? "Unknown gzip error"
        self.kind = Kind(code: code)
    }

    var localizedDescription: String {

        self.message
    }
}

extension GzipError.Kind {

    fileprivate init(code: Int32) {

        switch code {
        case Z_STREAM_ERROR:
            self = .stream
        case Z_DATA_ERROR:
            self = .data
        case Z_MEM_ERROR:
            self = .memory
        case Z_BUF_ERROR:
            self = .buffer
        case Z_VERSION_ERROR:
            self = .version
        default:
            self = .unknown(code: Int(code))
        }
    }
}

extension Data {

    /// Whether the receiver is compressed in gzip format.
    var isGzipped: Bool {

        self.starts(with: [0x1f, 0x8b])  // check magic number// check magic number
    }

    /// Create a new `Data` instance by compressing the receiver using zlib.
    /// Throws an error if compression failed.
    ///
    /// The `wBits` parameter allows for managing the size of the history buffer. The possible values are:
    ///
    ///     Value       Window size logarithm    Input
    ///     +9 to +15   Base 2                   Includes zlib header and trailer
    ///     -9 to -15   Absolute value of wbits  No header and trailer
    ///     +25 to +31  Low 4 bits of the value  Includes gzip header and trailing checksum
    ///
    /// - Parameter wBits: Manage the size of the history buffer.
    /// - Returns: Gzip-compressed `Data` instance.
    /// - Throws: `GzipError`
    func gzipped(wBits: Int32 = MAX_WBITS + 16) throws(GzipError) -> Data {

        guard !self.isEmpty else {
            return Data()
        }

        var stream = z_stream()
        var status: Int32

        status = deflateInit2_(
            &stream,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            wBits,
            MAX_MEM_LEVEL,
            Z_DEFAULT_STRATEGY,
            ZLIB_VERSION,
            Int32(DataSize.stream)
        )

        guard status == Z_OK else {
            // deflateInit2 returns:
            // Z_VERSION_ERROR  The zlib library version is incompatible with the version assumed by the caller.
            // Z_MEM_ERROR      There was not enough memory.
            // Z_STREAM_ERROR   A parameter is invalid.

            throw GzipError(code: status, msg: stream.msg)
        }

        var data = Data(capacity: DataSize.chunk)
        repeat {
            if Int(stream.total_out) >= data.count {
                data.count += DataSize.chunk
            }

            let inputCount = self.count
            let outputCount = data.count

            self.withUnsafeBytes { (inputPointer: UnsafeRawBufferPointer) in
                stream.next_in = UnsafeMutablePointer<Bytef>(
                    mutating: inputPointer.bindMemory(to: Bytef.self).baseAddress!
                ).advanced(by: Int(stream.total_in))
                stream.avail_in = uInt(inputCount) - uInt(stream.total_in)

                data.withUnsafeMutableBytes { (outputPointer: UnsafeMutableRawBufferPointer) in
                    stream.next_out = outputPointer.bindMemory(to: Bytef.self).baseAddress!.advanced(
                        by: Int(stream.total_out)
                    )
                    stream.avail_out = uInt(outputCount) - uInt(stream.total_out)

                    status = deflate(&stream, Z_FINISH)

                    stream.next_out = nil
                }

                stream.next_in = nil
            }

        } while stream.avail_out == 0 && status != Z_STREAM_END

        guard deflateEnd(&stream) == Z_OK, status == Z_STREAM_END else {
            throw GzipError(code: status, msg: stream.msg)
        }

        data.count = Int(stream.total_out)

        return data
    }

    /// Create a new `Data` instance by decompressing the receiver using zlib.
    /// Throws an error if decompression failed.
    ///
    /// The `wBits` parameter allows for managing the size of the history buffer. The possible values are:
    ///
    ///     Value                        Window size logarithm    Input
    ///     +8 to +15                    Base 2                   Includes zlib header and trailer
    ///     -8 to -15                    Absolute value of wbits  Raw stream with no header and trailer
    ///     +24 to +31 = 16 + (8 to 15)  Low 4 bits of the value  Includes gzip header and trailer
    ///     +40 to +47 = 32 + (8 to 15)  Low 4 bits of the value  zlib or gzip format
    ///
    /// - Parameter wBits: Manage the size of the history buffer.
    /// - Returns: Gzip-decompressed `Data` instance.
    /// - Throws: `GzipError`
    func gunzipped(wBits: Int32 = MAX_WBITS + 32) throws(GzipError) -> Data {

        guard !self.isEmpty else {
            return Data()
        }

        var data = Data(capacity: self.count * 2)
        var totalIn: uLong = 0
        var totalOut: uLong = 0

        repeat {
            var stream = z_stream()
            var status: Int32

            status = inflateInit2_(&stream, wBits, ZLIB_VERSION, Int32(DataSize.stream))

            guard status == Z_OK else {
                // inflateInit2 returns:
                // Z_VERSION_ERROR   The zlib library version is incompatible with the version assumed by the caller.
                // Z_MEM_ERROR       There was not enough memory.
                // Z_STREAM_ERROR    A parameters are invalid.

                throw GzipError(code: status, msg: stream.msg)
            }

            repeat {
                if Int(totalOut + stream.total_out) >= data.count {
                    data.count += self.count / 2
                }

                let inputCount = self.count
                let outputCount = data.count

                self.withUnsafeBytes { (inputPointer: UnsafeRawBufferPointer) in
                    let inputStartPosition = totalIn + stream.total_in
                    stream.next_in = UnsafeMutablePointer<Bytef>(
                        mutating: inputPointer.bindMemory(to: Bytef.self).baseAddress!
                    ).advanced(by: Int(inputStartPosition))
                    stream.avail_in = uInt(inputCount) - uInt(inputStartPosition)

                    data.withUnsafeMutableBytes { (outputPointer: UnsafeMutableRawBufferPointer) in
                        let outputStartPosition = totalOut + stream.total_out
                        stream.next_out = outputPointer.bindMemory(to: Bytef.self).baseAddress!.advanced(
                            by: Int(outputStartPosition)
                        )
                        stream.avail_out = uInt(outputCount) - uInt(outputStartPosition)

                        status = inflate(&stream, Z_SYNC_FLUSH)

                        stream.next_out = nil
                    }

                    stream.next_in = nil
                }
            } while status == Z_OK

            totalIn += stream.total_in

            guard inflateEnd(&stream) == Z_OK, status == Z_STREAM_END else {
                // inflate returns:
                // Z_DATA_ERROR   The input data was corrupted (input stream not conforming to the zlib format or incorrect check value).
                // Z_STREAM_ERROR The stream structure was inconsistent (for example if next_in or next_out was NULL).
                // Z_MEM_ERROR    There was not enough memory.
                // Z_BUF_ERROR    No progress is possible or there was not enough room in the output buffer when Z_FINISH is used.
                throw GzipError(code: status, msg: stream.msg)
            }

            totalOut += stream.total_out

        } while totalIn < self.count

        data.count = Int(totalOut)

        return data
    }
}

private enum DataSize {

    static let chunk = 1 << 14
    static let stream = MemoryLayout<z_stream>.size
}
