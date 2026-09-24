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

extension YubiOTP {

    /// The default URI prefix to which the slot's OTP is appended over NFC.
    public static let defaultNDEFURI = URL(string: "https://my.yubico.com/yk/#")!
}

extension YubiOTP {
    static func buildNDEFConfig(uri: URL) throws(YubiOTP.SessionError) -> Data {
        let value = uri.absoluteString
        var payload = Data()

        // Abbreviate a known prefix to its identifier byte; 0 means "no prefix".
        if let index = ndefURLPrefixes.firstIndex(where: { value.hasPrefix($0) }) {
            payload.append(UInt8(index + 1))
            payload.append(Data(value.dropFirst(ndefURLPrefixes[index].count).utf8))
        } else {
            payload.append(0)
            payload.append(Data(value.utf8))
        }

        guard payload.count <= ndefDataSize else {
            throw .illegalArgument("NDEF payload is too large, at most \(ndefDataSize) bytes", source: .here())
        }

        var config = Data([UInt8(payload.count), 0x55])  // URI record ('U').
        config.append(payload)
        config.append(Data(count: ndefDataSize - payload.count))
        return config
    }
}

private let ndefDataSize = 54

// URI prefixes that an NDEF URI record abbreviates. The index plus one is the identifier code.
private let ndefURLPrefixes = [
    "http://www.", "https://www.", "http://", "https://", "tel:", "mailto:",
    "ftp://anonymous:anonymous@", "ftp://ftp.", "ftps://", "sftp://", "smb://", "nfs://",
    "ftp://", "dav://", "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:", "sip:",
    "sips:", "tftp:", "btspp://", "btl2cap://", "btgoep://", "tcpobex://", "irdaobex://",
    "file://", "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:", "urn:epc:",
    "urn:nfc:",
]
