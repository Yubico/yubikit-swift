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

@preconcurrency import CryptoTokenKit.TKSmartCard
import Foundation
import OSLog

/// A connection to the YubiKey utilizing the USB-C port and the TKSmartCard implementation from
/// the CryptoTokenKit framework.
@available(iOS 16.0, macOS 13.0, *)
public struct USBSmartCardConnection: Sendable {
    public let slot: USBSmartCard.YubiKeyDevice

    public static var availableDevices: [USBSmartCard.YubiKeyDevice] {
        get async throws {
            try await SmartCardConnectionsManager.shared.availableDevices()
        }
    }

    private var didClose: Promise<Error?> {
        get async throws { try await SmartCardConnectionsManager.shared.didClose(for: self) }
    }

    private var isConnected: Bool {
        get async throws { await SmartCardConnectionsManager.shared.isConnected(for: self) }
    }
}

extension USBSmartCardConnection: SmartCardConnection {

    // @TraceScope
    public static func connection() async throws -> SmartCardConnection {
        while true {
            guard let slot = try await availableDevices.first else {
                try await Task.sleep(for: .seconds(1))
                continue
            }
            return try await connection(slot: slot)
        }
    }

    // @TraceScope
    public static func connection(slot: USBSmartCard.YubiKeyDevice) async throws -> SmartCardConnection {
        try await SmartCardConnectionsManager.shared.connect(slot: slot)
    }

    // @TraceScope
    public func close(error: Error?) async {
        try? await didClose.fulfill(error)
        trace(message: "disconnect called on sessionManager")
    }

    // @TraceScope
    public func connectionDidClose() async -> Error? {
        try? await didClose.value()
    }

    // @TraceScope
    public func send(data: Data) async throws -> Data {

        guard try await isConnected else {
            trace(message: "no connection – throwing .noConnection")
            throw ConnectionError.noConnection
        }
        let response = try await SmartCardConnectionsManager.shared.transmit(request: data, for: self)
        trace(message: "transmit returned \(response.count) bytes")
        return response
    }
}

// USBSmartCardConnection specific errors
public enum SmartCardConnectionError: Error, Sendable {
    /// CryptoTokenKit failed to return TKSmartCardSlotManager.default
    case unsupported
    /// CryptoTokenKit returned no slots
    case noAvailableSlots
    /// CryptoTokenKit failed to return a TKSmartCardSlot.
    case getSmartCardSlotFailed
    /// CryptoTokenKit failed to start a session for the TKSmartCard.
    case beginSessionFailed
}

// Used to indentify a card / connection.
// Exposed when calling `USBSmartCardConnection.availableDevices`
// and when creating a connection with USBSmartCardConnection.connection(slot:)
public enum USBSmartCard {
    public struct YubiKeyDevice: Sendable, Hashable, CustomStringConvertible {
        public let name: String

        public var description: String { name }

        fileprivate init?(name: String) {
            guard name.lowercased().contains("yubikey") else { return nil }
            self.name = name
        }
    }
}

// MARK: - Internal helpers / extensions
extension USBSmartCardConnection: HasSmartCardLogger {}
extension SmartCardConnectionsManager: HasSmartCardLogger {}

// MARK: - Private helpers

// MARK: Handles TKSmartCard creation and connections, plus KVOs for changes
private final actor SmartCardConnectionsManager {

    // Singleton
    static let shared = SmartCardConnectionsManager()
    private init() {}

    // We must lock around slot.makeSmartCard() and card.beginSession()
    // we can only establish a connection at once
    private var isEstablishing: Bool = false

    private var slotManager: TKSmartCardSlotManager {
        get throws {
            guard let manager = TKSmartCardSlotManager.default else {
                assertionFailure("🪪 No default TKSmartCardSlotManager, check entitlements for com.apple.smartcard.")
                trace(message: "no slotsManager – throwing .unsupported")
                throw SmartCardConnectionError.unsupported
            }

            return manager
        }
    }

    private var connections = [USBSmartCard.YubiKeyDevice: ConnectionState]()

    // @TraceScope
    func didClose(for connection: USBSmartCardConnection) throws -> Promise<Error?> {
        guard let state = connections[connection.slot] else {
            throw ConnectionError.noConnection
        }

        return state.didClose
    }

    // @TraceScope
    func isConnected(for connection: USBSmartCardConnection) -> Bool {
        guard let card = connections[connection.slot]?.card else {
            return false
        }

        return card.isValid && card.currentProtocol != []
    }

    // @TraceScope
    func transmit(request: Data, for connection: USBSmartCardConnection) async throws -> Data {
        guard let card = connections[connection.slot]?.card else {
            throw ConnectionError.noConnection
        }

        return try await card.transmit(request)
    }

    // @TraceScope
    func connect(slot: USBSmartCard.YubiKeyDevice) async throws -> USBSmartCardConnection {
        // if there is already a connection for this slot we throw `ConnectionError.busy`.
        // The caller must close the connection first.
        guard connections[slot] == nil else {
            throw ConnectionError.busy
        }

        // To proceed with a new connection we need to acquire a lock
        // so we can guarantee balanced calls to beginSession()
        guard !isEstablishing else { throw ConnectionError.cancelled }
        defer { isEstablishing = false }
        isEstablishing = true

        // get a TKSmartCard from a slot
        // can fail if no cards are connected
        let tkSlot = try await slotManager.getSlot(withName: slot.name)

        guard let tkSlot else {
            trace(message: "slot came back as nil")
            throw SmartCardConnectionError.getSmartCardSlotFailed
        }

        guard let card = tkSlot.makeSmartCard() else {
            trace(message: "slot.makeSmartCard() returned nil")
            throw SmartCardConnectionError.beginSessionFailed
        }

        trace(message: "will call card.beginSession()")
        guard try await card.beginSession() == true else {
            trace(message: "card.beginSession() failed")
            throw SmartCardConnectionError.beginSessionFailed
        }
        trace(message: "card.beginSession() succeded")

        // create and save a new connection state
        let state = ConnectionState(card: card)
        connections[slot] = state

        // register for the eventual clean up when the connection is closed
        Task {
            _ = try await state.didClose.value()
            state.card.endSession()
            if connections[slot] === state {
                connections[slot] = nil
            }
        }

        // return the newly established connection
        return USBSmartCardConnection(slot: slot)
    }

    func availableDevices() async throws -> [USBSmartCard.YubiKeyDevice] {
        try slotManager.slotNames.compactMap(USBSmartCard.YubiKeyDevice.init)
    }
}

private class ConnectionState {
    let card: TKSmartCard

    let didClose = Promise<Error?>()

    private let isValidObserver: NSKeyValueObservation
    private let stateObserver: NSKeyValueObservation

    // @TraceScope
    init(card: TKSmartCard) {
        self.card = card

        stateObserver = card.observe(\.currentProtocol, options: [.new]) { [didClose] card, _ in
            if card.currentProtocol == [] {
                Task { await didClose.fulfill(nil) }
            }
        }

        isValidObserver = card.observe(\.isValid, options: [.new]) { [didClose] card, _ in
            if !card.isValid {
                Task { await didClose.fulfill(nil) }
            }
        }
    }
}
