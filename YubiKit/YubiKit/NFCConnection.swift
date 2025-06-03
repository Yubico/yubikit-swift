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
@preconcurrency import CoreNFC
import Foundation
import OSLog

/// A NFC connection to the YubiKey.
///
/// The  NFCConnection is short lived and should be closed as soon as the commands sent to the YubiKey have finished processing. It is up to the user of
/// the connection to close it when it no longer is needed. As long as the connection is open the NFC modal will cover the lower part of the iPhone screen.
/// In addition to the ``close(error:)`` method defined in the Connection protocol the NFCConnection has an additional ``close(message:)``
/// method that will close the connection and set the alertMessage of the NFC alert to the provided message.
///
/// > Note: NFC is only supported on iPhones from iPhone 6 and forward. It will not work on iPads since there's no NFC chip in these devices.
public struct NFCConnection: Connection, Sendable {
    fileprivate let tag: ISO7816Identifier

    /// Presents the NFC sheet and returns a live ``NFCConnection`` once the user
    /// taps a YubiKey.
    ///
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``NFCConnectionError.unsupported`` when NFC is unavailable or
    ///           ``ConnectionError.cancelled`` if another connection is in flight.
    // @TraceScope
    public static func connection() async throws -> Connection {
        trace(message: "NFCConnection.connection() – requesting new connection")
        let conn = try await NFCConnectionManager.shared.connect(message: nil)
        trace(message: "NFCConnection.connection() – connection established")
        return conn
    }

    /// Same as ``connection()`` but allows customizing the system sheet’s
    /// instructional `alertMessage`.
    ///
    /// - Parameter message: Optional text shown while scanning.
    // @TraceScope
    public static func connection(alertMessage message: String?) async throws -> Connection {
        trace(message: "NFCConnection.connection(alertMessage:) – requesting new connection")
        let conn = try await NFCConnectionManager.shared.connect(message: message)
        trace(message: "NFCConnection.connection(alertMessage:) – connection established")
        return conn
    }

    // MARK: - UI helpers

    // @TraceScope
    public func setAlertMessage(_ message: String) async {
        trace(message: "NFCConnection.setAlertMessage(\"\(message)\") – not yet implemented")
        return await NFCConnectionManager.shared.set(alertMessage: message)
    }

    // MARK: - Lifecycle

    // @TraceScope
    public func close(error: Error?) async {
        if let error = error {
            trace(message: "NFCConnection.close(error:) – closing with error msg: \(String(describing: error))")
            await NFCConnectionManager.shared.stop(with: .failure(error))
        } else {
            trace(message: "NFCConnection.close(error: nil) – closing with success")
            await NFCConnectionManager.shared.stop(with: .success(nil))
        }
    }

    // @TraceScope
    public func close(message: String? = nil) async {
        trace(message: "NFCConnection.close(message:) – closing with error msg: \(String(describing: message))")
        await NFCConnectionManager.shared.stop(with: .success(message))
    }

    // @TraceScope
    public func connectionDidClose() async -> Error? {
        trace(message: "NFCConnection.connectionDidClose() – awaiting dismissal")
        do {
            try await NFCConnectionManager.shared.didClose(for: self)
        } catch {
            trace(message: "NFCConnection.connectionDidClose() – dismissed, error: \(String(describing: error))")
            return error
        }
        trace(message: "NFCConnection.connectionDidClose() – dismissed")
        return nil
    }

    // MARK: - APDU

    // @TraceScope
    /// Sends an APDU over the active NFC link.
    ///
    /// - Parameter data: Raw APDU bytes.
    /// - Returns: The response payload concatenated with status words SW1 SW2.
    /// - Throws: ``ConnectionError.noConnection`` if the tag is no longer
    ///           attached or ``NFCConnectionError.malformedAPDU`` when `data`
    ///           is not a valid APDU.
    public func send(data: Data) async throws -> Data {
        trace(message: "NFCConnection.send(data:) – \(data.count) bytes")
        let response = try await NFCConnectionManager.shared.transmit(request: data, for: self)
        trace(message: "NFCConnection.send(data:) – received \(response.count) bytes")
        return response
    }
}

// NFCConnection specific errors
public enum NFCConnectionError: Error {
    case failedToPoll
    case unsupported
    case malformedAPDU
}

// Downcast helper
extension Connection {
    public var nfcConnection: NFCConnection? {
        self as? NFCConnection
    }
}

// MARK: - Internal helpers / extensions
extension NFCConnection: HasNFCLogger {}
extension NFCConnectionManager: HasNFCLogger {}

// MARK: - Private helpers

/// Stable identifier for an ISO‑7816 tag.
///
/// Wraps the tag UID in a `Hashable` value so it can be used as a
/// dictionary key (e.g. in `Set`s or `Promise` maps).
private struct ISO7816Identifier: Hashable {
    let data: Data

    init(_ data: Data) {
        self.data = data
    }

    static func == (lhs: ISO7816Identifier, rhs: ISO7816Identifier) -> Bool { lhs.data == rhs.data }
    func hash(into hasher: inout Hasher) { hasher.combine(data) }
}

extension NFCISO7816Tag {
    fileprivate typealias Identifier = ISO7816Identifier
}

///
/// Handles Core NFC session orchestration, guarantees balanced lifetime
/// calls, and multiplexes ``NFCConnection`` instances to the single
/// `NFCTagReaderSession` permitted by the system.
///
/// > Important: All methods are `actor`‑isolated; use `await` when
/// interacting from outside the actor context.
private final actor NFCConnectionManager: NSObject {

    static let shared = NFCConnectionManager()
    private override init() { super.init() }

    private var isEstablishing: Bool = false
    private var connection: Promise<NFCConnection>? = nil
    private var didCloseConnection: Promise<Error?>? = nil

    private var currentState = State.inactive
    private func set(state: State) {
        currentState = state
    }

    // @TraceScope
    func set(alertMessage: String) {
        Task { @MainActor in
            await currentState.session?.alertMessage = alertMessage
        }
    }

    // @TraceScope
    func didClose(for connection: NFCConnection) async throws {
        trace(message: "Manager.didClose(for:) – tracking closure for tag \(connection.tag)")

        guard let tag = currentState.tag,
            connection.tag == .init(tag.identifier),
            let didCloseConnection
        else { return }

        if let error = try await didCloseConnection.value() {
            throw error
        }
    }

    // @TraceScope
    func transmit(request: Data, for connection: NFCConnection) async throws -> Data {
        trace(message: "Manager.transmit – \(request.count) bytes to tag \(connection.tag)")
        guard let tag = currentState.tag,
            connection.tag == .init(tag.identifier)
        else {
            trace(message: "Manager.transmit – noConnection")
            throw ConnectionError.noConnection
        }

        guard let apdu = NFCISO7816APDU(data: request) else {
            trace(message: "Manager.transmit – malformed APDU")
            throw NFCConnectionError.malformedAPDU
        }

        let (data, sw1, sw2) = try await tag.sendCommand(apdu: apdu)
        trace(message: "Manager.transmit – got \(data.count) bytes, SW: \(String(format:"%02X%02X", sw1, sw2))")
        return data + sw1.data + sw2.data
    }

    // @TraceScope
    func connect(message alertMessage: String?) async throws -> NFCConnection {
        trace(message: "Manager.connect – begin")
        guard NFCReaderSession.readingAvailable else {
            trace(message: "Manager.connect – unsupported")
            throw NFCConnectionError.unsupported
        }

        // To proceed with a new connection we need to acquire a lock
        guard !isEstablishing else { throw ConnectionError.cancelled }
        defer { isEstablishing = false }
        isEstablishing = true

        // Close the previous connection before establishing a new one
        switch currentState {
        case .inactive:
            break
        case .connected, .scanning:
            await stop(with: .success(nil))
        }

        // Start polling
        guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil) else {
            throw NFCConnectionError.failedToPoll
        }
        if let alertMessage { session.alertMessage = alertMessage }
        currentState = .scanning(session)
        connection = .init()
        session.begin()

        return try await connection!.value()
    }

    // @TraceScope
    func stop(with result: Result<String?, Error>) async {
        trace(message: "Manager.stop(with:) - result: \(String(describing: result))")

        switch result {
        case .success(nil), .failure:
            currentState.session?.invalidate()
        case let .success(errorMessage):
            currentState.session?.invalidate(errorMessage: errorMessage!)
        }

        currentState.session?.invalidate()
        // Workaround for the NFC session being active for an additional 4 seconds after
        // invalidate() has been called on the session.
        try? await Task.sleep(nanoseconds: 5_000_000_000)
        switch result {
        case .success:
            await didCloseConnection?.fulfill(nil)
        case let .failure(error):
            await didCloseConnection?.fulfill(error)
        }
        currentState = .inactive
        connection = nil
        didCloseConnection = nil
    }

    // @TraceScope
    func connected(session: NFCTagReaderSession, tag: NFCISO7816Tag) async {
        trace(message: "Manager.connected(session:tag:) - tag: \(String(describing: tag.identifier))")
        didCloseConnection = .init()
        currentState = .connected(session, tag)
        await connection?.fulfill(.init(tag: .init(tag.identifier)))
    }
}

extension NFCConnectionManager: NFCTagReaderSessionDelegate {

    // MARK: - NFCTagReaderSessionDelegate

    // @TraceScope
    nonisolated public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        trace(message: "NFCTagReaderSessionDelegate: Session did become active")
    }

    // @TraceScope
    nonisolated public func tagReaderSession(
        _ session: NFCTagReaderSession,
        didInvalidateWithError error: Error
    ) {
        trace(message: "NFCTagReaderSessionDelegate: Session invalidated – \(error.localizedDescription)")

        Task { await stop(with: .failure(error)) }
    }

    // @TraceScope
    nonisolated public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {

        trace(message: "NFCTagReaderSessionDelegate: Session didDetectTags – \(tags.count) tags")
        let iso7816Tags = tags.compactMap { tag -> NFCISO7816Tag? in
            if case .iso7816(let iso7816Tag) = tag { return iso7816Tag }
            return nil
        }

        guard let firstTag = iso7816Tags.first else {
            trace(message: "NFCTagReaderSessionDelegate: No ISO-7816 tag found")
            return
        }

        Task { await connected(session: session, tag: firstTag) }
    }
}

// MARK: - State enum
private enum State: Sendable {
    case inactive
    case scanning(NFCTagReaderSession)
    case connected(NFCTagReaderSession, NFCISO7816Tag)

    var session: NFCTagReaderSession? {
        switch self {
        case .inactive: return nil
        case let .scanning(session), let .connected(session, _): return session
        }
    }

    var tag: NFCISO7816Tag? {
        switch self {
        case .inactive, .scanning: return nil
        case let .connected(_, tag): return tag
        }
    }
}

#endif
