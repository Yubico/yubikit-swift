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

    /// Send CBOR-encoded CTAP2 command and receive CBOR response
    ///
    /// This is the main entry point for CTAP2 protocol commands like authenticatorGetInfo,
    /// authenticatorMakeCredential, authenticatorGetAssertion, etc.
    ///
    /// - Parameter payload: CBOR-encoded command data (command byte + optional CBOR parameters)
    /// - Returns: Async sequence of status updates, ending with `.finished(response)`
    private func sendCTAPCommandStream<O: CBOR.Decodable & Sendable>(
        payload: Data
    ) -> CTAP.StatusStream<O> where Error == CTAP.SessionError {

        let stream: CTAP.StatusStream<O> = .init { continuation in
            Task {
                do throws(CTAP.SessionError) {
                    // Check capability support
                    guard self.supports(.cbor) else {
                        throw Error.featureNotSupported(source: .here())
                    }

                    // Send the request
                    try await self.sendRequest(cmd: Self.hidCommand(.cbor), payload: payload)

                    // Create cancel closure that calls the interface's cancel method
                    // Any errors during cancellation are yielded to the stream
                    let cancelClosure: @Sendable () async -> Void = { [weak self] in
                        do throws(CTAP.SessionError) {
                            try await self?.cancel()
                        } catch {
                            continuation.yield(error: error)
                        }
                    }

                    // Receive response with KEEPALIVE status updates
                    let responsePayload = try await self.receiveResponse(
                        expectedCommand: Self.hidCommand(.cbor)
                    ) { statusByte in
                        if let currentStatus: CTAP.Status<O> = CTAP.Status.fromKeepAlive(
                            statusByte: statusByte,
                            cancel: cancelClosure
                        ) {
                            continuation.yield(currentStatus)
                        }
                    }

                    // Parse CTAP response and yield final result
                    let result: O = try self.handleCTAP2Response(responsePayload)
                    continuation.yield(.finished(result))
                    continuation.finish()
                } catch {
                    continuation.yield(error: error)
                }
            }
        }

        return stream
    }
}
