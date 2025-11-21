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

// MARK: - CBORInterface Conformance (HID/USB Transport)

extension FIDOInterface: CBORInterface where Error == CTAP.SessionError {
    func send<I: CBOR.Encodable, O: CBOR.Decodable & Sendable>(
        command: CTAP.Command,
        payload: I
    ) -> CTAP.StatusStream<O> {
        var requestData = Data([command.rawValue])
        let cborData = payload.cbor().encode()
        requestData.append(cborData)

        // TODO: Validate message size against authenticatorInfo.maxMsgSize

        return sendCTAPCommandStream(payload: requestData)
    }
}
