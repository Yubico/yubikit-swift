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
    /// - Returns: Async sequence of status updates, ending with `.finished(response)` or errors
    func send<I: CBOR.Encodable, O: CBOR.Decodable & Sendable>(
        command: CTAP2.Command,
        payload: I
    ) -> CTAP2.StatusStream<O>

    /// Send a CTAP2 command with CBOR payload that has no response body.
    ///
    /// - Parameters:
    ///   - command: The CTAP2 command
    ///   - payload: CBOR-encodable payload (will be CBOR-encoded)
    /// - Returns: Async sequence of status updates, ending with `.finished(())`
    func send<I: CBOR.Encodable>(
        command: CTAP2.Command,
        payload: I
    ) -> CTAP2.StatusStream<Void>
}

extension CBORInterface {
    /// Send a CTAP2 command with no payload and a CBOR-decodable response.
    func send<O: CBOR.Decodable & Sendable>(
        command: CTAP2.Command
    ) -> CTAP2.StatusStream<O> {
        send(command: command, payload: nil as CBOR.Value?)
    }

    /// Send a CTAP2 command with no payload and no response body.
    func send(
        command: CTAP2.Command
    ) -> CTAP2.StatusStream<Void> {
        send(command: command, payload: nil as CBOR.Value?)
    }

    /// Send a CTAP2 command with no payload, returning raw CBOR.
    func send(
        command: CTAP2.Command
    ) -> CTAP2.StatusStream<CBOR.Value> {
        send(command: command, payload: nil as CBOR.Value?)
    }
}

// MARK: - Private Helpers

extension CBORInterface where Error == CTAP2.SessionError {
    /// Handle CTAP2 response for commands with no response body.
    func handleCTAP2Response(_ responseData: Data) throws(Error) {
        guard !responseData.isEmpty else {
            throw .cborError(CBOR.Error.unexpectedEndOfData, source: .here())
        }

        let statusByte = responseData[0]

        if statusByte == 0x00 {
            let cborData = Data(responseData.dropFirst())
            guard cborData.isEmpty else {
                throw .responseParseError("Expected empty response body for this command", source: .here())
            }
        } else {
            throw .ctapError(CTAP2.Error.from(errorCode: statusByte), source: .here())
        }
    }

    /// Handle CTAP2 response with CBOR-decodable body.
    func handleCTAP2Response<O: CBOR.Decodable>(_ responseData: Data) throws(Error) -> O {
        guard !responseData.isEmpty else {
            throw .cborError(CBOR.Error.unexpectedEndOfData, source: .here())
        }

        let statusByte = responseData[0]

        if statusByte == 0x00 {
            // Convert to Data to reset indices to 0 (dropFirst returns Slice<Data>)
            let cborData = Data(responseData.dropFirst())

            guard !cborData.isEmpty else {
                throw .cborError(CBOR.Error.unexpectedEndOfData, source: .here())
            }

            let decoded: O?
            do {
                decoded = try cborData.decode()
            } catch {
                throw .cborError(error, source: .here())
            }

            guard let decoded else {
                throw .responseParseError("Failed to decode CBOR response", source: .here())
            }

            return decoded
        } else {
            throw .ctapError(CTAP2.Error.from(errorCode: statusByte), source: .here())
        }
    }
}
