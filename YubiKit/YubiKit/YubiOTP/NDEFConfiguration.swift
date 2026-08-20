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

private let ndefDataSize = 54

/// Prefixes the NDEF record can abbreviate to a single identifier byte. Order is significant — the
/// index into this table plus one is the identifier code.
private let ndefURLPrefixes = [
    "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
    "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://",
    "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:",
    "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://",
    "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:",
    "urn:nfc:",
]

extension YubiOTP {

    /// The default URI written when configuring a slot for NDEF.
    public static let defaultNDEFURI = "https://my.yubico.com/yk/#"

    /// The kind of NDEF record a slot emits over NFC.
    public enum NDEFType: UInt8, Sendable {
        /// A text record.
        case text = 0x54  // 'T'
        /// A URI record.
        case uri = 0x55  // 'U'
    }

    /// Builds the 56-byte NDEF configuration block: `length ‖ type ‖ payload[54]`.
    ///
    /// Mirrors `yubikit.yubiotp._build_ndef_config`.
    static func buildNDEFConfig(
        value: String?,
        type: NDEFType
    ) throws(YubiOTPSessionError) -> Data {
        var payload = Data()

        switch type {
        case .uri:
            let uri = value ?? defaultNDEFURI
            // Abbreviate a known prefix to its identifier byte; 0 means "no prefix".
            if let index = ndefURLPrefixes.firstIndex(where: { uri.hasPrefix($0) }) {
                payload.append(UInt8(index + 1))
                payload.append(Data(uri.dropFirst(ndefURLPrefixes[index].count).utf8))
            } else {
                payload.append(0)
                payload.append(Data(uri.utf8))
            }
        case .text:
            payload.append(contentsOf: Array("\u{02}en".utf8))
            payload.append(Data((value ?? "").utf8))
        }

        guard payload.count <= ndefDataSize else {
            throw .illegalArgument("NDEF payload is too large, at most \(ndefDataSize) bytes", source: .here())
        }

        var config = Data([UInt8(payload.count), type.rawValue])
        config.append(payload)
        config.append(Data(count: ndefDataSize - payload.count))
        return config
    }
}
