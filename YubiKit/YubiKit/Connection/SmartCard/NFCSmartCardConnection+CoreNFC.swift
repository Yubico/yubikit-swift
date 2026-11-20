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
@preconcurrency import CoreNFC
import Logging

// MARK: - NFCConnectionManagerWrapper

// Actor wrapper that bridges async/await to the serial queue-based NFCConnectionManager
actor NFCConnectionManagerWrapper {
    static let shared = NFCConnectionManagerWrapper()
    private let nfcStateManager: NFCConnectionManager
    private let queue = DispatchQueue(label: "com.yubico.NFCConnectionManager", attributes: [])

    private init() {
        nfcStateManager = NFCConnectionManager(nfcQueue: queue)
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

    func stop(id: UUID, with result: Result<String?, Error>) async {
        await withCheckedContinuation { continuation in
            queue.async {
                self.nfcStateManager.stop(id: id, with: result) {
                    continuation.resume()
                }
            }
        }
    }

    func connect(message alertMessage: String?, lifetime: ConnectionLifetime) async throws(SmartCardConnectionError) {
        let queue = self.queue
        let manager = self.nfcStateManager
        let request = NFCConnectRequest(lifetime: lifetime)
        do {
            try Task.checkCancellation()
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    queue.async {
                        request.install(continuation)
                        manager.connect(message: alertMessage, request: request)
                    }
                }
            } onCancel: {
                queue.async {
                    request.cancel()
                    manager.cancelPendingConnection(for: request)
                }
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

    func set(alertMessage: String, id: UUID) {
        queue.async {
            self.nfcStateManager.set(alertMessage: alertMessage, id: id)
        }
    }
}

// Accessed only on the NFC manager queue.
private final class NFCConnectRequest: @unchecked Sendable {
    let lifetime: ConnectionLifetime

    init(lifetime: ConnectionLifetime) { self.lifetime = lifetime }

    private var continuation: CheckedContinuation<Void, Error>?
    private(set) var isCancelled = false
    private var isComplete = false

    func install(_ continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
        if isCancelled { complete(.failure(SmartCardConnectionError.cancelled)) }
    }

    func cancel() {
        isCancelled = true
        complete(.failure(SmartCardConnectionError.cancelled))
    }

    func complete(_ result: Result<Void, Error>) {
        guard !isComplete, let continuation else { return }
        isComplete = true
        self.continuation = nil
        continuation.resume(with: result)
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
    private var activeRequest: NFCConnectRequest?

    // iOS fails a reader session begun while the previous session's sheet is still being
    // dismissed (NFCReaderError 202, "Session invalidated unexpectedly"), so wait this long
    // after an invalidation before beginning a new session.
    private static let sessionCooldown: DispatchTimeInterval = .seconds(2)
    private var lastInvalidation: DispatchTime?

    init(nfcQueue: DispatchQueue) {
        self.nfcQueue = nfcQueue
    }

    func set(alertMessage: String, id: UUID) {
        guard currentState.lifetime?.id == id, let session = currentState.session else { return }
        // alertMessage affects the system NFC UI and must be updated on main thread
        Task { @MainActor in
            session.alertMessage = alertMessage
        }
    }

    func transmit(
        request: Data,
        for connection: NFCSmartCardConnection,
        completion: @escaping @Sendable (Result<Data, Error>) -> Void
    ) {
        guard let tag = currentState.tag,
            currentState.lifetime?.id == connection.lifetime.id
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

    func stop(id: UUID, with result: Result<String?, Error>, completion: @escaping @Sendable () -> Void) {
        logger.debug("Stopping NFC session")

        // If already inactive, complete immediately
        guard currentState.lifetime?.id == id, currentState.phase != .inactive else {
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
    func cancelPendingConnection(for request: NFCConnectRequest) {
        guard activeRequest === request, currentState.phase == .scanning else { return }
        stop(id: request.lifetime.id, with: .success(nil)) {}
    }

    func connect(
        message alertMessage: String?,
        request: NFCConnectRequest
    ) {
        logger.debug("Starting NFC connection")
        guard !request.isCancelled else { return }
        guard NFCReaderSession.readingAvailable else {
            logger.debug("NFC reading is unavailable")
            request.complete(.failure(SmartCardConnectionError.unsupported))
            return
        }

        // if there is already a connection for this slot we throw `SmartCardConnectionError.busy`.
        // The caller must close the connection first.
        switch currentState.phase {
        case .inactive:
            if let lastInvalidation, DispatchTime.now() < lastInvalidation + Self.sessionCooldown {
                logger.debug("Waiting for the previous NFC session to be dismissed")
                nfcQueue.asyncAfter(deadline: lastInvalidation + Self.sessionCooldown) { [weak self] in
                    self?.connect(message: alertMessage, request: request)
                }
                return
            }
        case .stopping:
            logger.debug("Waiting for the previous NFC session to stop")
            // Session is being invalidated - wait for it to complete then retry
            if let existing = currentState.stopCompletion {
                currentState.stopCompletion = { [weak self] in
                    existing()
                    self?.connect(message: alertMessage, request: request)
                }
            } else {
                currentState.stopCompletion = { [weak self] in
                    self?.connect(message: alertMessage, request: request)
                }
            }
            return
        case .scanning, .connected:
            logger.debug("NFC connection is already active or pending")
            // throw
            request.complete(.failure(SmartCardConnectionError.busy))
            return
        }

        // To proceed with a new connection we need to acquire a lock
        guard !isEstablishing else {
            logger.debug("NFC connection setup is already in progress")
            request.complete(.failure(SmartCardConnectionError.busy))
            return
        }
        isEstablishing = true

        // Start polling - use the same queue for all NFC operations
        guard let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nfcQueue) else {
            isEstablishing = false
            logger.debug("Failed to create NFC reader session")
            request.complete(.failure(SmartCardConnectionError.pollingFailed("Failed to create NFC reader session")))
            return
        }

        activeRequest = request
        currentState.setScanning(
            lifetime: request.lifetime,
            session: session,
            completion: { [weak self] result in
                self?.isEstablishing = false
                if self?.activeRequest === request { self?.activeRequest = nil }
                request.complete(result)
            }
        )

        if let alertMessage { session.alertMessage = alertMessage }
        session.begin()
    }

    func connected(session: NFCTagReaderSession, tag: NFCISO7816Tag) {
        logger.debug("NFC tag detected")

        guard currentState.phase == .scanning else { return }
        guard let connectionCompletion = currentState.connectionCompletion else {
            cleanup(session: session)
            return
        }

        currentState.setConnected(tag: tag)
        logger.debug("NFC connection established")

        connectionCompletion(.success(()))
    }

    private func cleanup(session: NFCTagReaderSession, error: Error? = nil) {
        guard currentState.session === session else {
            return
        }

        // Capture stopCompletion before reset clears it
        let stopCompletion = currentState.stopCompletion

        let closeError = currentState.closingError ?? error
        if let lifetime = currentState.lifetime {
            Task { await lifetime.didClose.fulfill(closeError) }
        }
        switch closeError {
        case .none:
            currentState.connectionCompletion?(Result.failure(SmartCardConnectionError.cancelledByUser))
        case let .some(error):
            currentState.connectionCompletion?(Result.failure(error))
        }

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
        lastInvalidation = .now()
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
    var connectionCompletion: (@Sendable (Result<Void, Error>) -> Void)?

    // Connected state
    var tag: NFCISO7816Tag?
    var lifetime: ConnectionLifetime?

    // Stop completion - called when session is fully invalidated
    var stopCompletion: (@Sendable () -> Void)?

    // The reason passed to close(error:), if any; Core NFC may report user cancellation instead.
    var closingError: Error?

    func reset() {
        phase = .inactive
        session = nil
        connectionCompletion = nil
        tag = nil
        lifetime = nil
        stopCompletion = nil
        closingError = nil
    }

    func setScanning(
        lifetime: ConnectionLifetime,
        session: NFCTagReaderSession,
        completion: @escaping @Sendable (Result<Void, Error>) -> Void
    ) {
        phase = .scanning
        self.session = session
        self.connectionCompletion = completion
        // Clear connected state
        tag = nil
        self.lifetime = lifetime
    }

    func setConnected(tag: NFCISO7816Tag) {
        phase = .connected
        self.tag = tag
        // Clear scanning state
        connectionCompletion = nil
    }
}

#endif  // os(iOS)
