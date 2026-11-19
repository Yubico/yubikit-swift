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

#if os(iOS)

import Foundation
import YubiKitTwinSupport

actor NFCConnectionManagerWrapper {
    static let shared = NFCConnectionManagerWrapper()
    private var active: State?
    private var isEstablishing = false

    private struct State {
        let identifier: ISO7816Identifier
        let channel: TwinKitSmartCardChannel
    }

    func connect(message: String?) async throws(SmartCardConnectionError) -> ISO7816Identifier {
        guard !Task.isCancelled else { throw .cancelled }
        guard TwinKitConfiguration.hasNFCReader else { throw .unsupported }
        guard active == nil, !isEstablishing else { throw .busy }
        isEstablishing = true
        defer { isEstablishing = false }
        while try !TwinKitConfiguration.isPresent(.nfc) {
            do { try await Task.sleep(for: .milliseconds(100)) } catch { throw .cancelled }
        }
        let channel: TwinKitSmartCardChannel
        do { channel = try await TwinKitBackend.shared.openSmartCard(transport: .nfc) } catch {
            throw .setupFailed("TwinKit NFC open failed", error)
        }
        if Task.isCancelled {
            channel.close(error: nil)
            throw .cancelled
        }
        let identifier = ISO7816Identifier(Data(UUID().uuidString.utf8))
        active = State(identifier: identifier, channel: channel)
        return identifier
    }

    func transmit(request: Data, for connection: NFCSmartCardConnection) async throws(SmartCardConnectionError) -> Data
    {
        guard let state = active, state.identifier == connection.tag else { throw .connectionLost }
        do {
            let response = try await state.channel.send(request)
            guard active?.identifier == state.identifier else { throw SmartCardConnectionError.connectionLost }
            return response
        } catch let error as SmartCardConnectionError {
            throw error
        } catch TwinKitSupportError.connectionLost {
            throw .connectionLost
        } catch {
            throw .transmitFailed("TwinKit NFC exchange failed", error)
        }
    }

    func didClose(for connection: NFCSmartCardConnection) async throws {
        guard let state = active, state.identifier == connection.tag else { return }
        if let error = await state.channel.waitUntilClosed() { throw error }
    }

    func stop(with result: Result<String?, Error>) {
        guard let state = active else { return }
        active = nil
        switch result {
        case .success: state.channel.close(error: nil)
        case .failure(let error): state.channel.close(error: error)
        }
    }

    // The transport accepts message changes; only CoreNFC owns the native sheet.
    func set(alertMessage: String) {}
}

#endif
