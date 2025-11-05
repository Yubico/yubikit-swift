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

    /// Send a CTAP2 command without payload.
    ///
    /// The request format is: [command_byte]
    /// The response format is: [status_byte][optional_cbor_response]
    ///
    /// - Parameters:
    ///   - command: The CTAP2 command
    /// - Returns: Decoded CBOR response, or nil if no response data
    /// - Throws: CTAP or CBOR error
    func send<O: CBOR.Decodable>(
        command: CTAP.Command
    ) async throws(Error) -> O?
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

        do {
            let cborData = try payload.cbor().encode()
            requestData.append(cborData)
        } catch {
            throw .cborError(error, source: .here())
        }

        // TODO: Validate message size against authenticatorInfo.maxMsgSize

        let responseData = try await self.cbor(payload: requestData)
        return try handleCTAP2Response(responseData)
    }

    func send<O: CBOR.Decodable>(
        command: CTAP.Command
    ) async throws(Error) -> O? {
        let requestData = Data([command.rawValue])
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

        do {
            let cborData = try payload.cbor().encode()
            requestData.append(cborData)
        } catch {
            throw .cborError(error, source: .here())
        }

        let apdu = APDU(cla: 0x00, ins: 0x10, p1: 0x00, p2: 0x00, command: requestData)
        let responseData = try await send(apdu: apdu)
        return try handleCTAP2Response(responseData)
    }

    func send<O: CBOR.Decodable>(
        command: CTAP.Command
    ) async throws(Error) -> O? {
        let requestData = Data([command.rawValue])
        let apdu = APDU(cla: 0x00, ins: 0x10, p1: 0x00, p2: 0x00, command: requestData)
        let responseData = try await send(apdu: apdu)
        return try handleCTAP2Response(responseData)
    }
}
