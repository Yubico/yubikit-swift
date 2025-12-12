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
///
/// - Note: This protocol is public to allow use in generic constraints, but conformance
///   is restricted to internal SDK types. External code cannot create new conforming types.
public protocol CBORInterface: Actor {

    /// The error type thrown by this interface.
    associatedtype Error: SessionError

    /// The firmware version of the connected device.
    var version: Version { get async }

    /// Maximum message size supported by the authenticator.
    var maxMsgSize: Int { get }

    /// Update the maximum message size after getInfo() returns.
    func setMaxMsgSize(_ size: Int)
}

/// Internal extension for CBOR-specific send methods.
/// These methods use internal CBOR types and are not exposed publicly.
extension CBORInterface {
    /// Send a CTAP2 command with CBOR payload.
    func send<I: CBOR.Encodable, O: CBOR.Decodable & Sendable>(
        command: CTAP2.Command,
        payload: I
    ) -> CTAP2.StatusStream<O> {
        fatalError("Must be implemented by conforming types")
    }

    /// Send a CTAP2 command with CBOR payload that has no response body.
    func send<I: CBOR.Encodable>(
        command: CTAP2.Command,
        payload: I
    ) -> CTAP2.StatusStream<Void> {
        fatalError("Must be implemented by conforming types")
    }
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
