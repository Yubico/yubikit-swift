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

extension SmartCardConnection {
    /// Returns this connection as an NFCSmartCardConnection if it is one.
    public var nfcConnection: NFCSmartCardConnection? {
        self as? NFCSmartCardConnection
    }
}

#if !(YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator))

@preconcurrency import CoreNFC
import Logging

// MARK: - Public API

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
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public init() async throws(SmartCardConnectionError) {
        Self.logger.debug("Requesting NFC connection")
        let tag = try await NFCConnectionManagerWrapper.shared.connect(message: nil)
        self.init(tag: tag)
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Parameter alertMessage: Optional text shown while scanning.
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public init(alertMessage: String?) async throws(SmartCardConnectionError) {
        Self.logger.debug("Requesting NFC connection")
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
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public static func makeConnection() async throws(SmartCardConnectionError) -> NFCSmartCardConnection {
        Self.logger.debug("Requesting NFC connection")
        let tag = try await NFCConnectionManagerWrapper.shared.connect(message: nil)
        return NFCSmartCardConnection(tag: tag)
    }

    /// Creates a new NFC connection to a YubiKey.
    ///
    /// Presents the NFC sheet and waits for the user to tap a YubiKey to establish a connection.
    ///
    /// - Parameter message: Optional text shown while scanning.
    /// - Returns: A fully–established connection ready for APDU exchange.
    /// - Throws: ``SmartCardConnectionError.unsupported`` when NFC is unavailable or
    ///           ``SmartCardConnectionError.busy`` if there is already an active connection.
    public static func makeConnection(
        alertMessage message: String?
    ) async throws(SmartCardConnectionError) -> NFCSmartCardConnection {
        Self.logger.debug("Requesting NFC connection")
        let tag = try await NFCConnectionManagerWrapper.shared.connect(message: message)
        return NFCSmartCardConnection(tag: tag)
    }

    /// Sets the alert message displayed on the NFC scanning sheet.
    ///
    /// - Parameter message: The message to display while scanning.
    public func setAlertMessage(_ message: String) async {
        logger.debug("Updating NFC alert message")
        await NFCConnectionManagerWrapper.shared.set(alertMessage: message)
    }

    /// Closes the NFC connection with an optional error.
    ///
    /// - Parameter error: Optional error to indicate why the connection was closed.
    public func close(error: Error?) async {
        if let error = error {
            logger.debug(
                "Closing NFC connection with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
            await NFCConnectionManagerWrapper.shared.stop(with: .failure(error))
        } else {
            logger.debug("Closing NFC connection")
            await NFCConnectionManagerWrapper.shared.stop(with: .success(nil))
        }
    }

    /// Closes the NFC connection with a success message.
    ///
    /// - Parameter message: Optional success message to display when closing.
    public func close(message: String? = nil) async {
        logger.debug("Closing NFC connection")
        await NFCConnectionManagerWrapper.shared.stop(with: .success(message))
    }

    /// Waits for the connection to close and returns any error that caused the closure.
    ///
    /// - Returns: An error if the connection was closed due to an error, nil otherwise.
    public func waitUntilClosed() async -> Error? {
        logger.debug("Waiting for NFC connection to close")
        do {
            try await NFCConnectionManagerWrapper.shared.didClose(for: self)
        } catch {
            logger.debug(
                "NFC connection closed with an error",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
            return error
        }
        logger.debug("NFC connection closed")
        return nil
    }

    /// Sends an APDU over the active NFC link.
    ///
    /// - Parameter data: Raw APDU bytes.
    /// - Returns: The response payload concatenated with status words SW1 SW2.
    /// - Throws: ``SmartCardConnectionError.connectionLost`` if the tag is no longer
    ///           attached or ``SmartCardConnectionError.malformedData`` when `data`
    ///           is not a valid APDU.
    public func send(data: Data) async throws(SmartCardConnectionError) -> Data {
        logger.debug("Sending NFC request", metadata: ["bytes": .stringConvertible(data.count)])
        let response = try await NFCConnectionManagerWrapper.shared.transmit(request: data, for: self)
        logger.debug("Received NFC response", metadata: ["bytes": .stringConvertible(response.count)])
        return response
    }

}

// MARK: - Extensions

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

    func transmit(request: Data, for connection: NFCSmartCardConnection) async throws(SmartCardConnectionError) -> Data
    {
        do {
            return try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    self.nfcStateManager.transmit(request: request, for: connection) { result in
                        continuation.resume(with: result)
                    }
                }
            }
        } catch {
            // Map NFC errors to SmartCardConnectionError
            throw SmartCardConnectionError.transmitFailed("NFC transmit failed", flatten: error)
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

    func connect(message alertMessage: String?) async throws(SmartCardConnectionError) -> ISO7816Identifier {
        let queue = self.queue
        let manager = self.nfcStateManager
        do {
            try Task.checkCancellation()
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    queue.async {
                        manager.connect(message: alertMessage) { result in
                            continuation.resume(with: result)
                        }
                    }
                }
            } onCancel: {
                // Cancelled while the NFC sheet is up: invalidate the session so it dismisses.
                queue.async { manager.cancelPendingConnection() }
            }
        } catch {
            NFCConnectionManager.logger.debug(
                "NFC connection setup failed",
                metadata: [
                    "errorType": .string(String(reflecting: type(of: error))),
                    "errorDomain": .string((error as NSError).domain),
                    "errorCode": .stringConvertible((error as NSError).code),
                ]
            )
            if Task.isCancelled { throw .cancelled }
            throw .setupFailed("Failed to begin SmartCard session", flatten: error)
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

    func set(alertMessage: String) {
        // alertMessage affects the system NFC UI and must be updated on main thread
        Task { @MainActor in
            currentState.session?.alertMessage = alertMessage
        }
    }

    func didClose(for connection: NFCSmartCardConnection, completion: @escaping @Sendable (Result<Void, Error>) -> Void)
    {

        switch currentState.phase {
        case .inactive, .scanning, .stopping:
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

    func transmit(
        request: Data,
        for connection: NFCSmartCardConnection,
        completion: @escaping @Sendable (Result<Data, Error>) -> Void
    ) {
        guard let tag = currentState.tag,
            connection.tag == .init(tag.identifier)
        else {
            logger.debug("Cannot send on a closed NFC connection")
            completion(.failure(SmartCardConnectionError.connectionLost))
            return
        }

        guard let apdu = NFCISO7816APDU(data: request) else {
            logger.debug("Cannot send malformed NFC APDU")
            completion(.failure(SmartCardConnectionError.malformedData("Invalid APDU format")))
            return
        }

        logger.traceRequest(request)
        tag.sendCommand(apdu: apdu) { (data, sw1, sw2, error) in
            if let error = error {
                completion(.failure(error))
            } else {
                self.logger.debug(
                    "Received NFC response status",
                    metadata: ["sw1": .stringConvertible(sw1), "sw2": .stringConvertible(sw2)]
                )
                let response = data + sw1.data + sw2.data
                self.logger.traceResponse(response)
                completion(.success(response))
            }
        }
    }

    func stop(with result: Result<String?, Error>, completion: @escaping @Sendable () -> Void) {
        logger.debug("Stopping NFC session")

        // If already inactive, complete immediately
        guard currentState.phase != .inactive else {
            completion()
            return
        }

        // Store completion to be called when didInvalidateWithError fires.
        // Chain with existing completion if stop() is called multiple times.
        if let existing = currentState.stopCompletion {
            currentState.stopCompletion = {
                existing()
                completion()
            }
        } else {
            currentState.stopCompletion = completion
        }

        // If already stopping, don't invalidate again
        guard currentState.phase != .stopping else { return }
        currentState.phase = .stopping

        switch result {
        case let .failure(error):
            // App-initiated invalidation is often reported by iOS as user cancellation.
            currentState.closingError = error
            currentState.session?.invalidate(errorMessage: error.localizedDescription)
        case let .success(message):
            if let message = message {
                currentState.session?.alertMessage = message
            }
            currentState.session?.invalidate()
        }
    }

    // Dismisses the reader sheet of a connection still waiting for a tap. A connection that
    // was established before the cancellation arrived belongs to the caller and is kept.
    func cancelPendingConnection() {
        guard currentState.phase == .scanning else { return }
        stop(with: .success(nil)) {}
    }

    func connect(
        message alertMessage: String?,
        completion: @escaping @Sendable (Result<ISO7816Identifier, Error>) -> Void
    ) {
        logger.debug("Starting NFC connection")
        guard NFCReaderSession.readingAvailable else {
            logger.debug("NFC reading is unavailable")
            completion(.failure(SmartCardConnectionError.unsupported))
            return
        }

        // if there is already a connection for this slot we throw `SmartCardConnectionError.busy`.
        // The caller must close the connection first.
        switch currentState.phase {
        case .inactive:
            // lets continue
            break
        case .stopping:
            logger.debug("Waiting for the previous NFC session to stop")
            // Session is being invalidated - wait for it to complete then retry
            if let existing = currentState.stopCompletion {
                currentState.stopCompletion = { [weak self] in
                    existing()
                    self?.connect(message: alertMessage, completion: completion)
                }
            } else {
                currentState.stopCompletion = { [weak self] in
                    self?.connect(message: alertMessage, completion: completion)
                }
            }
            return
        case .scanning, .connected:
            logger.debug("NFC connection is already active or pending")
            // throw
            completion(.failure(SmartCardConnectionError.busy))
            return
        }

        // To proceed with a new connection we need to acquire a lock
        guard !isEstablishing else {
            logger.debug("NFC connection setup is already in progress")
            completion(.failure(SmartCardConnectionError.cancelled))
            return
        }
        isEstablishing = true

        // Start polling - use the same queue for all NFC operations
        guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nfcQueue) else {
            isEstablishing = false
            logger.debug("Failed to create NFC reader session")
            completion(.failure(SmartCardConnectionError.pollingFailed("Failed to create NFC reader session")))
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

    func connected(session: NFCTagReaderSession, tag: NFCISO7816Tag) {
        logger.debug("NFC tag detected")

        guard let connectionCompletion = currentState.connectionCompletion else {
            cleanup(session: session)
            return
        }

        currentState.setConnected(tag: tag)
        logger.debug("NFC connection established")

        connectionCompletion(Result.success(.init(tag.identifier)))
    }

    private func cleanup(session: NFCTagReaderSession, error: Error? = nil) {
        guard currentState.session === session else {
            return
        }

        // Capture stopCompletion before reset clears it
        let stopCompletion = currentState.stopCompletion

        switch currentState.closingError ?? error {
        case .none:
            currentState.didCloseCallback?(nil as Error?)
            currentState.connectionCompletion?(Result.failure(SmartCardConnectionError.cancelledByUser))
        case let .some(error):
            currentState.didCloseCallback?(error)
            currentState.connectionCompletion?(Result.failure(error))
        }

        currentState.didCloseCallback = nil

        currentState.reset()

        // Signal that the session is fully invalidated
        stopCompletion?()
    }
}

// MARK: - NFCTagReaderSessionDelegate

extension NFCConnectionManager: NFCTagReaderSessionDelegate, HasNFCLogger {

    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        logger.debug("NFC reader session active")
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        logger.debug(
            "NFC reader session invalidated",
            metadata: [
                "errorType": .string(String(reflecting: type(of: error))),
                "errorDomain": .string((error as NSError).domain),
                "errorCode": .stringConvertible((error as NSError).code),
            ]
        )

        let nfcError = error as? NFCReaderError
        if let nfcError {
            logger.debug(
                "NFC reader invalidation reason",
                metadata: ["code": .stringConvertible(nfcError.code.rawValue)]
            )
        }

        let mappedError: Error?
        switch nfcError?.code {
        case .some(.readerSessionInvalidationErrorUserCanceled):
            mappedError = nil  // user cancelled, no error
        default:
            mappedError = error
        }

        cleanup(session: session, error: mappedError)
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        logger.debug("NFC tags detected", metadata: ["count": .stringConvertible(tags.count)])
        let iso7816Tags = tags.compactMap { tag -> NFCISO7816Tag? in
            if case .iso7816(let iso7816Tag) = tag { return iso7816Tag }
            return nil
        }

        guard let firstTag = iso7816Tags.first else {
            logger.debug("No ISO-7816 NFC tag found")
            return
        }

        if session === currentState.session {
            connected(session: session, tag: firstTag)
        } else {
            cleanup(session: session, error: SmartCardConnectionError.cancelled)
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
        case stopping
    }

    var phase: Phase = .inactive

    // Scanning state
    var session: NFCTagReaderSession?
    var connectionCompletion: (@Sendable (Result<ISO7816Identifier, Error>) -> Void)?

    // Connected state
    var tag: NFCISO7816Tag?
    var didCloseCallback: (@Sendable (Error?) -> Void)?

    // Stop completion - called when session is fully invalidated
    var stopCompletion: (@Sendable () -> Void)?

    // The reason passed to close(error:), if any; Core NFC may report user cancellation instead.
    var closingError: Error?

    func reset() {
        phase = .inactive
        session = nil
        connectionCompletion = nil
        tag = nil
        didCloseCallback = nil
        stopCompletion = nil
        closingError = nil
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

#endif  // !(YUBIKIT_TWINKIT && DEBUG && targetEnvironment(simulator))

#endif  // os(iOS)
