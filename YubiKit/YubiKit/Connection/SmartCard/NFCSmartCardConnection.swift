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

// MARK: - Public API

public enum NFCConnectionError: Error, Sendable {
    case failedToPoll
    case unsupported
    case malformedAPDU
}

/// A NFC connection to the YubiKey.
///
/// The  NFCSmartCardConnection is short lived and should be closed as soon as the commands sent to the YubiKey have finished processing. It is up to the user of
/// the connection to close it when it no longer is needed. As long as the connection is open the NFC modal will cover the lower part of the iPhone screen.
/// In addition to the ``close(error:)`` method defined in the SmartCardConnection protocol the NFCSmartCardConnection has an additional ``close(success:)``
/// method that will close the connection and set the alertMessage of the NFC alert to the provided message.
///
/// > Note: NFC is only supported on iPhones from iPhone 6 and forward. It will not work on iPads since there's no NFC chip in these devices.
public struct NFCSmartCardConnection: SmartCardConnection, Sendable {
    fileprivate let tag: ISO7816Identifier

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Throws: ``NFCConnectionError.unsupported`` when NFC is unavailable or
    ///           ``ConnectionError.busy`` if there is already an active connection.
    public convenience init() async throws {
        let tag = try await NFCConnectionManagerWrapper.shared.connect(message: nil)
        self.init(tag: tag)
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Parameter alertMessage: Optional text shown while scanning.
    /// - Throws: ``NFCConnectionError.unsupported`` when NFC is unavailable or
    ///           ``ConnectionError.busy`` if there is already an active connection.
    public convenience init(alertMessage: String?) async throws {
        let tag = try await NFCConnectionManagerWrapper.shared.connect(message: alertMessage)
        self.init(tag: tag)
    }

    fileprivate init(tag: ISO7816Identifier) {
        self.tag = tag
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``NFCConnectionError.unsupported`` when NFC is unavailable or
    ///           ``ConnectionError.busy`` if there is already an active connection.
    // @TraceScope
    public static func connection() async throws -> NFCSmartCardConnection {
        trace(message: "NFCSmartCardConnection.connection() – requesting new connection")
        let tag = try await NFCConnectionManagerWrapper.shared.connect(message: nil)
        trace(message: "NFCSmartCardConnection.connection() – connection established")
        return NFCSmartCardConnection(tag: tag)
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Parameter message: Optional text shown while scanning.
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``NFCConnectionError.unsupported`` when NFC is unavailable or
    ///           ``ConnectionError.busy`` if there is already an active connection.
    // @TraceScope
    public static func connection(alertMessage message: String?) async throws -> NFCSmartCardConnection {
        trace(message: "NFCSmartCardConnection.connection(alertMessage:) – requesting new connection")
        let tag = try await NFCConnectionManagerWrapper.shared.connect(message: message)
        trace(message: "NFCSmartCardConnection.connection(alertMessage:) – connection established")
        return NFCSmartCardConnection(tag: tag)
    }

    // @TraceScope
    public func setAlertMessage(_ message: String) async {
        trace(message: "NFCSmartCardConnection.setAlertMessage(:)")
        await NFCConnectionManagerWrapper.shared.set(alertMessage: message)
    }

    // @TraceScope
    public func close(error: Error?) async {
        if let error = error {
            trace(
                message: "NFCSmartCardConnection.close(error:) – closing with error msg: \(String(describing: error))"
            )
            await NFCConnectionManagerWrapper.shared.stop(with: .failure(error))
        } else {
            trace(message: "NFCSmartCardConnection.close(error: nil) – closing with success")
            await NFCConnectionManagerWrapper.shared.stop(with: .success(nil))
        }
    }

    // @TraceScope
    public func close(message: String? = nil) async {
        trace(
            message: "NFCSmartCardConnection.close(message:) – closing with success msg: \(String(describing: message))"
        )
        await NFCConnectionManagerWrapper.shared.stop(with: .success(message))
    }

    // @TraceScope
    public func connectionDidClose() async -> Error? {
        trace(message: "NFCSmartCardConnection.connectionDidClose() – awaiting dismissal")
        do {
            try await NFCConnectionManagerWrapper.shared.didClose(for: self)
        } catch {
            trace(
                message: "NFCSmartCardConnection.connectionDidClose() – dismissed, error: \(String(describing: error))"
            )
            return error
        }
        trace(message: "NFCSmartCardConnection.connectionDidClose() – dismissed")
        return nil
    }

    // @TraceScope
    /// Sends an APDU over the active NFC link.
    ///
    /// - Parameter data: Raw APDU bytes.
    /// - Returns: The response payload concatenated with status words SW1 SW2.
    /// - Throws: ``ConnectionError.noConnection`` if the tag is no longer
    ///           attached or ``NFCConnectionError.malformedAPDU`` when `data`
    ///           is not a valid APDU.
    public func send(data: Data) async throws -> Data {
        trace(message: "NFCSmartCardConnection.send(data:) – \(data.count) bytes")
        let response = try await NFCConnectionManagerWrapper.shared.transmit(request: data, for: self)
        trace(message: "NFCSmartCardConnection.send(data:) – received \(response.count) bytes")
        return response
    }

}

// MARK: - Extensions

extension SmartCardConnection {
    public var nfcConnection: NFCSmartCardConnection? {
        self as? NFCSmartCardConnection
    }
}

extension NFCSmartCardConnection: HasNFCLogger {}

// MARK: - Private helpers

// Stable identifier for an ISO‑7816 tag.
// Wraps the tag UID in a `Hashable` value so it can be used as a dictionary key.
private struct ISO7816Identifier: Hashable {
    let data: Data

    init(_ data: Data) {
        self.data = data
    }

    static func == (lhs: ISO7816Identifier, rhs: ISO7816Identifier) -> Bool { lhs.data == rhs.data }
    func hash(into hasher: inout Hasher) { hasher.combine(data) }
}

extension NFCISO7816Tag {
    private typealias Identifier = ISO7816Identifier
}

// MARK: - NFCConnectionManagerWrapper

// Actor wrapper that bridges async/await to the serial queue-based NFCConnectionManager
private actor NFCConnectionManagerWrapper {
    static let shared = NFCConnectionManagerWrapper()
    private let nfcStateManager: NFCConnectionManager
    private let queue = DispatchQueue(label: "com.yubico.NFCConnectionManager", attributes: [])

    private init() {
        nfcStateManager = NFCConnectionManager(nfcQueue: queue)
    }

    func didClose(for connection: NFCSmartCardConnection) async throws {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.nfcStateManager.didClose(for: connection) { result in
                    continuation.resume(with: result)
                }
            }
        }
    }

    func transmit(request: Data, for connection: NFCSmartCardConnection) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.nfcStateManager.transmit(request: request, for: connection) { result in
                    continuation.resume(with: result)
                }
            }
        }
    }

    func stop(with result: Result<String?, Error>) async {
        await withCheckedContinuation { continuation in
            queue.async {
                self.nfcStateManager.stop(with: result) {
                    continuation.resume()
                }
            }
        }
    }

    func connect(message alertMessage: String?) async throws -> ISO7816Identifier {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                self.nfcStateManager.connect(message: alertMessage) { result in
                    continuation.resume(with: result)
                }
            }
        }
    }

    func set(alertMessage: String) {
        queue.async {
            self.nfcStateManager.set(alertMessage: alertMessage)
        }
    }
}

// Handles Core NFC session orchestration, guarantees balanced lifetime
// calls, and multiplexes NFCSmartCardConnection instances to the single
// NFCTagReaderSession permitted by the system.
// Thread safety is managed by nfcQueue.
// @unchecked Sendable: Safe because all access is serialized through nfcQueue
private final class NFCConnectionManager: NSObject, @unchecked Sendable {

    private var isEstablishing: Bool = false
    private let currentState = NFCState()
    private let nfcQueue: DispatchQueue

    init(nfcQueue: DispatchQueue) {
        self.nfcQueue = nfcQueue
    }

    // @TraceScope
    func set(alertMessage: String) {
        // alertMessage affects the system NFC UI and must be updated on main thread
        Task { @MainActor in
            currentState.session?.alertMessage = alertMessage
        }
    }

    // @TraceScope
    func didClose(for connection: NFCSmartCardConnection, completion: @escaping @Sendable (Result<Void, Error>) -> Void)
    {
        trace(message: "Manager.didClose(for:) – tracking closure for tag \(connection.tag)")

        switch currentState.phase {
        case .inactive, .scanning:
            completion(.success(()))
        case .connected:
            guard let tag = currentState.tag, connection.tag == .init(tag.identifier) else {
                completion(.success(()))
                return
            }

            // Add callback for when the connection closes
            currentState.didCloseCallback = { error in
                if let error = error {
                    completion(.failure(error))
                } else {
                    completion(.success(()))
                }
            }
        }
    }

    // @TraceScope
    func transmit(
        request: Data,
        for connection: NFCSmartCardConnection,
        completion: @escaping @Sendable (Result<Data, Error>) -> Void
    ) {
        trace(message: "Manager.transmit – \(request.count) bytes to tag \(connection.tag)")
        guard let tag = currentState.tag,
            connection.tag == .init(tag.identifier)
        else {
            trace(message: "Manager.transmit – noConnection")
            completion(.failure(ConnectionError.noConnection))
            return
        }

        guard let apdu = NFCISO7816APDU(data: request) else {
            trace(message: "Manager.transmit – malformed APDU")
            completion(.failure(NFCConnectionError.malformedAPDU))
            return
        }

        tag.sendCommand(apdu: apdu) { (data, sw1, sw2, error) in
            if let error = error {
                completion(.failure(error))
            } else {
                self.trace(
                    message: "Manager.transmit – got \(data.count) bytes, SW: \(String(format:"%02X%02X", sw1, sw2))"
                )
                completion(.success(data + sw1.data + sw2.data))
            }
        }
    }

    // @TraceScope
    func stop(with result: Result<String?, Error>, completion: @escaping @Sendable () -> Void) {
        trace(message: "Manager.stop(with:) - result: \(String(describing: result))")

        switch result {
        case let .failure(error):
            currentState.session?.invalidate(errorMessage: error.localizedDescription)
        case let .success(message):
            if let message = message {
                currentState.session?.alertMessage = message
            }
            currentState.session?.invalidate()
        }

        completion()
    }

    // @TraceScope
    func connect(
        message alertMessage: String?,
        completion: @escaping @Sendable (Result<ISO7816Identifier, Error>) -> Void
    ) {
        trace(message: "Manager.connect – begin")
        guard NFCReaderSession.readingAvailable else {
            trace(message: "Manager.connect – unsupported")
            completion(.failure(NFCConnectionError.unsupported))
            return
        }

        // if there is already a connection for this slot we throw `ConnectionError.busy`.
        // The caller must close the connection first.
        switch currentState.phase {
        case .inactive:
            // lets continue
            break
        case .scanning, .connected:
            // throw
            completion(.failure(ConnectionError.busy))
            return
        }

        // To proceed with a new connection we need to acquire a lock
        guard !isEstablishing else {
            completion(.failure(ConnectionError.cancelled))
            return
        }
        isEstablishing = true

        // Start polling - use the same queue for all NFC operations
        guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nfcQueue) else {
            isEstablishing = false
            completion(.failure(NFCConnectionError.failedToPoll))
            return
        }

        currentState.setScanning(
            session: session,
            completion: { [weak self] (result: Result<ISO7816Identifier, Error>) in
                self?.isEstablishing = false
                completion(result)
            }
        )

        if let alertMessage { session.alertMessage = alertMessage }
        session.begin()
    }

    // @TraceScope
    func connected(session: NFCTagReaderSession, tag: NFCISO7816Tag) {
        trace(message: "Manager.connected(session:tag:) - tag: \(String(describing: tag.identifier))")

        guard let connectionCompletion = currentState.connectionCompletion else {
            cleanup(session: session)
            return
        }

        currentState.setConnected(tag: tag)

        connectionCompletion(Result.success(.init(tag.identifier)))
    }

    private func cleanup(session: NFCTagReaderSession, error: Error? = nil) {
        guard currentState.session === session else {
            return
        }

        switch error {
        case .none:
            currentState.didCloseCallback?(nil as Error?)
            currentState.connectionCompletion?(Result.failure(ConnectionError.cancelledByUser))
        case let .some(error):
            currentState.didCloseCallback?(error)
            currentState.connectionCompletion?(Result.failure(error))
        }

        currentState.didCloseCallback = nil

        currentState.reset()
    }
}

// MARK: - NFCTagReaderSessionDelegate

extension NFCConnectionManager: NFCTagReaderSessionDelegate, HasNFCLogger {

    // @TraceScope
    nonisolated public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        trace(message: "NFCTagReaderSessionDelegate: Session did become active")
    }

    // @TraceScope
    nonisolated public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        trace(message: "NFCTagReaderSessionDelegate: Session invalidated – \(error.localizedDescription)")

        let nfcError = error as? NFCReaderError

        let mappedError: Error?
        switch nfcError?.code {
        case .some(.readerSessionInvalidationErrorUserCanceled):
            mappedError = nil  // user cancelled, no error
        default:
            mappedError = error
        }

        cleanup(session: session, error: mappedError)
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

        if session === currentState.session {
            connected(session: session, tag: firstTag)
        } else {
            cleanup(session: session, error: ConnectionError.cancelled)
        }
    }
}

// MARK: - NFCState

// Mutable state for NFC connection lifecycle
private class NFCState: @unchecked Sendable {
    enum Phase {
        case inactive
        case scanning
        case connected
    }

    var phase: Phase = .inactive

    // Scanning state
    var session: NFCTagReaderSession?
    var connectionCompletion: (@Sendable (Result<ISO7816Identifier, Error>) -> Void)?

    // Connected state
    var tag: NFCISO7816Tag?
    var didCloseCallback: (@Sendable (Error?) -> Void)?

    func reset() {
        phase = .inactive
        session = nil
        connectionCompletion = nil
        tag = nil
        didCloseCallback = nil
    }

    func setScanning(
        session: NFCTagReaderSession,
        completion: @escaping @Sendable (Result<ISO7816Identifier, Error>) -> Void
    ) {
        phase = .scanning
        self.session = session
        self.connectionCompletion = completion
        // Clear connected state
        tag = nil
        didCloseCallback = nil
    }

    func setConnected(tag: NFCISO7816Tag) {
        phase = .connected
        self.tag = tag
        // Clear scanning state
        connectionCompletion = nil
    }
}

#endif
