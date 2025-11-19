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

/// Protocol for interfaces that can perform CBOR-encoded CTAP2 operations.
///
/// This protocol abstracts the communication layer for CTAP2/CBOR commands,
/// allowing them to work over different transports that support CBOR messaging.
/// Currently implemented by ``FIDOInterface`` for HID/USB communication and
/// ``SmartCardInterface`` for NFC communication.
protocol CBORInterface: Actor {

    /// The error type thrown by this interface.
    associatedtype Error: SessionError

    var version: Version { get async }

    /// Send a CTAP2 command with CBOR payload.
    ///
    /// The request format is: [command_byte][cbor_payload]
    /// The response format is: [status_byte][optional_cbor_response]
    ///
    /// - Parameters:
    ///   - command: The CTAP2 command
    ///   - payload: CBOR-encodable payload (will be CBOR-encoded)
    /// - Returns: Decoded CBOR response, or nil if no response data
    /// - Throws: CTAP or CBOR error
    func send<I: CBOR.Encodable, O: CBOR.Decodable>(
        command: CTAP.Command,
        payload: I
    ) async throws(Error) -> O?

    /// Cancel any pending operation on this session.
    ///
    /// Aborts ongoing operations such as waiting for user interaction (touch prompt, PIN entry, etc.).
    func cancel() async throws(Error)
}

extension CBORInterface {
    func send<O: CBOR.Decodable>(command: CTAP.Command) async throws(Error) -> O? {
        try await send(command: command, payload: nil as CBOR.Value?)
    }

    func send(command: CTAP.Command) async throws(Error) {
        let _: CBOR.Value? = try await send(command: command, payload: nil as CBOR.Value?)
    }
}

// MARK: - Private Helpers

extension CBORInterface where Error: CBORError & CTAPError {
    fileprivate func handleCTAP2Response<O: CBOR.Decodable>(_ responseData: Data) throws(Error) -> O? {
        guard !responseData.isEmpty else {
            throw .cborError(CBOR.Error.unexpectedEndOfData, source: .here())
        }

        let statusByte = responseData[0]

        if statusByte == 0x00 {
            // Convert to Data to reset indices to 0 (dropFirst returns Slice<Data>)
            let cborData = Data(responseData.dropFirst())

            if cborData.isEmpty {
                return nil
            }

            do {
                return try cborData.decode()
            } catch {
                throw .cborError(error, source: .here())
            }
        } else {
            throw .ctapError(CTAP.Error.from(errorCode: statusByte), source: .here())
        }
    }
}

// MARK: - CBORInterface Conformance (HID/USB Transport)
extension FIDOInterface: CBORInterface where Error: CBORError & CTAPError {
    func send<I: CBOR.Encodable, O: CBOR.Decodable>(
        command: CTAP.Command,
        payload: I
    ) async throws(Error) -> O? {
        var requestData = Data([command.rawValue])
        let cborData = payload.cbor().encode()
        requestData.append(cborData)

        // TODO: Validate message size against authenticatorInfo.maxMsgSize

        let responseData = try await self.cbor(payload: requestData)
        return try handleCTAP2Response(responseData)
    }
}

// MARK: - CBORInterface Conformance (NFC/SmartCard Transport)
extension SmartCardInterface: CBORInterface where Error: CBORError & CTAPError {
    func send<I: CBOR.Encodable, O: CBOR.Decodable>(
        command: CTAP.Command,
        payload: I
    ) async throws(Error) -> O? {
        var requestData = Data([command.rawValue])
        let cborData = payload.cbor().encode()
        requestData.append(cborData)

        let responseData = try await sendCTAPCommand(requestData)
        return try handleCTAP2Response(responseData)
    }

    func cancel() async throws(Error) {
        shouldCancelCTAP = true
    }

    // Send CTAP command over CCID with support for keepalive polling and cancellation
    private func sendCTAPCommand(_ data: Data) async throws(Error) -> Data {

        let CLA: UInt8 = 0x80
        let NFCCTAP_MSG: UInt8 = 0x10
        let P1_KEEP_ALIVE: UInt8 = 0x00
        let P1_CANCEL_KEEP_ALIVE: UInt8 = 0x11
        let P1_GET_RESPONSE: UInt8 = 0x80
        let SW_KEEPALIVE: UInt16 = 0x9100
        let NFCCTAP_GETRESPONSE: UInt8 = 0x11

        // Clear 'shouldSendCancel' in case it has been trued before
        shouldCancelCTAP = false

        // Send initial CTAP command (handles 0x61 continuation automatically)
        let initialApdu = APDU(cla: CLA, ins: NFCCTAP_MSG, p1: P1_GET_RESPONSE, p2: 0x00, command: data)
        var response: Response = try await send(apdu: initialApdu)

        // TODO: Make sure it works by testing with a 5.8 key over USB
        // Poll with GET_RESPONSE while SW is 0x9100 (operation in progress)
        while true {

            let p1 = shouldCancelCTAP ? P1_CANCEL_KEEP_ALIVE : P1_KEEP_ALIVE

            // Send GET_RESPONSE to poll for completion
            let getResponseApdu = APDU(cla: CLA, ins: NFCCTAP_GETRESPONSE, p1: p1, p2: 0x00, command: nil)
            response = try await send(apdu: getResponseApdu)

            // exit loop when done
            guard response.responseStatus.rawStatus == SW_KEEPALIVE
            else { break }

            // avoid hammering the authenticator
            try? await Task.sleep(for: .milliseconds(100))
        }

        // Check final response status
        guard response.responseStatus.status == .ok else {
            throw .failedResponse(response.responseStatus, source: .here())
        }

        return response.data
    }
}
