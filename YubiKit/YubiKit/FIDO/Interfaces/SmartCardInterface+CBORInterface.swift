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

// MARK: - CBORInterface Conformance (NFC/SmartCard Transport)

extension SmartCardInterface: CBORInterface where Error == CTAP2.SessionError {

    func send<I: In, O: Out>(
        command: CTAP2.Command,
        payload: I
    ) -> CTAP2.StatusStream<O> {
        var requestData = Data([command.rawValue])
        let cborData = payload.cbor().encode()
        requestData.append(cborData)

        return execute(requestData)
    }

    func send<I: In>(
        command: CTAP2.Command,
        payload: I
    ) -> CTAP2.StatusStream<Void> {
        var requestData = Data([command.rawValue])
        let cborData = payload.cbor().encode()
        requestData.append(cborData)

        return execute(requestData)
    }

    private func execute<O: Out>(
        _ data: Data
    ) -> CTAP2.StatusStream<O> {
        execute(data) { (data: Data) throws(CTAP2.SessionError) -> O in
            try self.handleCTAP2Response(data)
        }
    }

    private func execute(
        _ data: Data
    ) -> CTAP2.StatusStream<Void> {
        execute(data) { (data: Data) throws(CTAP2.SessionError) in
            try self.handleCTAP2Response(data)
        }
    }

    /// Execute a CTAP command over CCID with support for keepalive polling.
    ///
    /// - Parameters:
    ///   - data: CBOR-encoded command data (command byte + optional CBOR parameters)
    ///   - parse: Closure to parse the response data
    /// - Returns: Async sequence of status updates, ending with `.finished(response)`
    private func execute<O: Sendable>(
        _ data: Data,
        parse: @escaping (Data) throws(CTAP2.SessionError) -> O
    ) -> CTAP2.StatusStream<O> {

        CTAP2.StatusStream<O> { continuation in
            Task {
                do throws(CTAP2.SessionError) {
                    let CLA: UInt8 = 0x80
                    let NFCCTAP_MSG: UInt8 = 0x10
                    let P1_KEEP_ALIVE: UInt8 = 0x00
                    let P1_CANCEL_KEEP_ALIVE: UInt8 = 0x11
                    let P1_GET_RESPONSE: UInt8 = 0x80
                    let SW_KEEPALIVE: UInt16 = 0x9100
                    let NFCCTAP_GETRESPONSE: UInt8 = 0x11

                    // Clear cancellation flag at the start of operation
                    self.shouldCancelCTAP = false

                    // Check message size
                    if data.count > self.maxMsgSize {
                        throw Error.ctapError(.requestTooLarge, source: .here())
                    }

                    // Create cancel closure that sets the flag
                    // Any errors during cancellation are yielded to the stream
                    let cancelClosure: @Sendable () async -> Void = { [weak self] in
                        do throws(CTAP2.SessionError) {
                            try await self?.cancel()
                        } catch {
                            continuation.yield(error: error)
                        }
                    }

                    // Send initial CTAP command
                    let initialApdu = APDU(cla: CLA, ins: NFCCTAP_MSG, p1: P1_GET_RESPONSE, p2: 0x00, command: data)

                    var response: Response
                    response = try await self.sendAllowingKeepalive(apdu: initialApdu)

                    // Poll with GET_RESPONSE while SW is 0x9100 (operation in progress)
                    while response.responseStatus.rawStatus == SW_KEEPALIVE {
                        // Parse keepalive status byte from response data
                        let statusByte = response.data.first ?? 0x01  // Default to processing
                        if let currentStatus: CTAP2.Status<O> = CTAP2.Status.fromKeepAlive(
                            statusByte: statusByte,
                            cancel: cancelClosure
                        ) {
                            continuation.yield(currentStatus)
                        }

                        // Avoid hammering the authenticator
                        try? await Task.sleep(for: .milliseconds(100))

                        // Use P1_CANCEL_KEEP_ALIVE if cancel() was called
                        let p1 = self.shouldCancelCTAP ? P1_CANCEL_KEEP_ALIVE : P1_KEEP_ALIVE

                        // Send GET_RESPONSE to poll for completion
                        let getResponseApdu = APDU(
                            cla: CLA,
                            ins: NFCCTAP_GETRESPONSE,
                            p1: p1,
                            p2: 0x00,
                            command: nil
                        )
                        response = try await self.sendAllowingKeepalive(apdu: getResponseApdu)
                    }

                    // Check final response status
                    guard response.status == .ok else {
                        throw Error.failedResponse(response, source: .here())
                    }

                    // Parse and yield final response
                    let result: O = try parse(response.data)
                    continuation.yield(.finished(result))
                    continuation.finish()

                } catch {
                    continuation.yield(error: error)
                }
            }
        }
    }

    private func sendAllowingKeepalive(
        apdu: APDU
    ) async throws(Error) -> Response {

        var response: Response
        do throws(CTAP2.SessionError) {
            response = try await self.send(apdu: apdu)
        } catch let CTAP2.SessionError.failedResponse(errorResponse, source: _) {
            // A SW_KEEPALIVE will enter here and we use the response directly
            response = errorResponse
        }

        return response
    }
}
