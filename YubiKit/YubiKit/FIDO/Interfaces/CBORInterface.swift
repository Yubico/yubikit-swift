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

/// Protocol for interfaces that can perform CBOR-encoded CTAP operations.
///
/// This protocol abstracts the communication layer for CTAP/CBOR commands,
/// allowing them to work over different transports that support CBOR messaging.
/// Currently implemented by ``FIDOInterface`` for HID/USB communication and
/// ``SmartCardInterface`` for NFC communication.
protocol CBORInterface: Actor {

    /// The error type thrown by this interface.
    associatedtype Error: SessionError

    var version: Version { get async }

    /// Send a CTAP command with CBOR payload.
    ///
    /// The request format is: [command_byte][cbor_payload]
    /// The response format is: [status_byte][optional_cbor_response]
    ///
    /// - Parameters:
    ///   - command: The CTAP command
    ///   - payload: CBOR-encodable payload (will be CBOR-encoded)
    /// - Returns: Async sequence of status updates, ending with `.finished(response)` or errors
    func send<I: CBOR.Encodable, O: CBOR.Decodable & Sendable>(
        command: CTAP.Command,
        payload: I
    ) -> CTAP.StatusStream<O>
}

extension CBORInterface {
    func send<O: CBOR.Decodable & Sendable>(
        command: CTAP.Command
    ) -> CTAP.StatusStream<O> {
        send(command: command, payload: nil as CBOR.Value?)
    }

    func send(
        command: CTAP.Command
    ) -> CTAP.StatusStream<CBOR.Value> {
        send(command: command, payload: nil as CBOR.Value?)
    }
}

// MARK: - Private Helpers

extension CBORInterface where Error == CTAP.SessionError {
    func handleCTAP2Response<O: CBOR.Decodable>(_ responseData: Data) throws(Error) -> O {
        guard !responseData.isEmpty else {
            throw .cborError(CBOR.Error.unexpectedEndOfData, source: .here())
        }

        let statusByte = responseData[0]

        if statusByte == 0x00 {
            // Convert to Data to reset indices to 0 (dropFirst returns Slice<Data>)
            let cborData = Data(responseData.dropFirst())

            // Special case: O is Optional<Never> (command with no response body)
            if O.self == Optional<Never>.self {
                guard cborData.isEmpty else {
                    throw .responseParseError("Expected empty response body for this command", source: .here())
                }
                return Optional<Never>.none as! O
            }

            // Normal case: decode CBOR response
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
            throw .ctapError(CTAP.Error.from(errorCode: statusByte), source: .here())
        }
    }
}
