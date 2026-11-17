import Foundation
import YubiKit

extension FidoUI {

    /// Connection and session construction boundary. Keeping these steps
    /// separate lets the controller own a connection while session setup
    /// performs asynchronous I/O.
    struct WiredTransportDriver: Sendable {
        let connect: @Sendable () async throws -> any Connection
        let makeSession: @Sendable (any Connection) async throws -> ActiveSession
        let devicePresent: @Sendable () async -> Bool
    }

    /// Production transport. Maintains a wired/HID session via a
    /// background loop; opens NFC sessions one-shot on demand. Built
    /// fresh per ceremony.
    actor TransportController: TransportControllerProtocol {

        private let origin: WebAuthn.Origin
        private let isPublicSuffix: WebAuthn.PublicSuffixChecker
        private let wiredDriver: WiredTransportDriver

        /// Backoff between failed open attempts. The OS doesn't surface
        /// "device became available" as an awaitable event, so hardware
        /// enumeration polls.
        private static let pollInterval: Duration = .milliseconds(500)

        private var current: Wired?
        private var openingConnection: Opening?
        /// Continuations parked in `awaitWired`, drained on every
        /// `setCurrent` (and on `cancel`).
        private var currentChangeWaiters: [CheckedContinuation<Void, Never>] = []

        /// A host-driven cancel runs in a separate Task from the parked
        /// `awaitWired` caller, so `Task.isCancelled` alone does not
        /// unwind the loop. Without this flag a parked waiter drains,
        /// sees `current == nil` / `isCancelled == false`, and re-parks.
        private var isShutdown = false

        #if os(iOS)
        private var nfcConnection: NFCSmartCardConnection?
        #endif
        private var loopTask: Task<Void, Never>?

        init(
            origin: WebAuthn.Origin,
            isPublicSuffix: @escaping WebAuthn.PublicSuffixChecker,
            wiredDriver: WiredTransportDriver? = nil
        ) {
            self.origin = origin
            self.isPublicSuffix = isPublicSuffix
            self.wiredDriver =
                wiredDriver
                ?? Self.makeWiredTransportDriver(
                    origin: origin,
                    isPublicSuffix: isPublicSuffix
                )
        }

        // MARK: - Lifecycle

        func start() {
            guard loopTask == nil, !isShutdown else { return }
            loopTask = Task { [weak self] in
                await self?.runLoop()
            }
        }

        func cancel() async {
            await stopWiredLoop()
            #if os(iOS)
            if let nfc = nfcConnection {
                nfcConnection = nil
                await nfc.close(error: nil)
            }
            #endif
        }

        /// Drop the wired-acquire loop without touching any held NFC
        /// session. After this call `awaitWired()` fails fast with
        /// `.cancelled` rather than parking forever.
        func stopWiredLoop() async {
            loopTask?.cancel()
            loopTask = nil
            let wired = current
            let opening = openingConnection
            isShutdown = true
            setCurrent(nil)
            openingConnection = nil
            if let wired { await wired.connection.close(error: nil) }
            if let opening { await opening.connection.close(error: nil) }
        }

        // MARK: - Wired API

        func wired() -> ActiveSession? {
            current?.session
        }

        func isWiredAvailable() async -> Bool {
            guard !isShutdown else { return false }
            if current != nil || openingConnection != nil { return true }
            let present = await wiredDriver.devicePresent()
            return !isShutdown && present
        }

        func awaitWired() async throws(FidoUI.Error) -> ActiveSession {
            while true {
                if Task.isCancelled || isShutdown { throw .cancelled }
                if let wired = current {
                    return wired.session
                }
                await waitForCurrentChange()
            }
        }

        private func waitForCurrentChange() async {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    currentChangeWaiters.append(continuation)
                }
            } onCancel: {
                Task { [weak self] in await self?.drainCurrentChangeWaiters() }
            }
        }

        private func drainCurrentChangeWaiters() {
            let parked = currentChangeWaiters
            currentChangeWaiters = []
            for continuation in parked { continuation.resume() }
        }

        // MARK: - NFC API (iOS only)

        #if os(iOS)
        func openNFC(alertMessage: String) async throws(FidoUI.Error) -> ActiveSession {
            if let prior = nfcConnection {
                nfcConnection = nil
                await prior.close(error: nil)
            }
            do {
                let conn = try await NFCSmartCardConnection(alertMessage: alertMessage)
                guard !Task.isCancelled else {
                    await conn.close(error: nil)
                    throw FidoUI.Error.cancelled
                }
                nfcConnection = conn
                let ctap = try await CTAP2.Session.makeSession(connection: conn)
                let info = try await ctap.getInfo()
                guard !Task.isCancelled else { throw FidoUI.Error.cancelled }
                let client = WebAuthn.Client(
                    session: ctap,
                    origin: origin,
                    isPublicSuffix: isPublicSuffix
                )
                return Self.makeActiveSession(client: client, info: info, ctap: ctap)
            } catch is CancellationError {
                await closeNFC(successMessage: nil)
                throw FidoUI.Error.cancelled
            } catch SmartCardConnectionError.cancelled, SmartCardConnectionError.cancelledByUser {
                await closeNFC(successMessage: nil)
                throw FidoUI.Error.cancelled
            } catch CTAP2.SessionError.connectionError(.cancelled, _),
                CTAP2.SessionError.connectionError(.cancelledByUser, _)
            {
                await closeNFC(successMessage: nil)
                throw FidoUI.Error.cancelled
            } catch let sessionError as CTAP2.SessionError {
                await closeNFC(successMessage: nil)
                if Task.isCancelled { throw FidoUI.Error.cancelled }
                if Self.isTransientTransportFailure(sessionError) {
                    throw .webAuthn(.authenticatorNotAvailable(source: .here()))
                }
                throw .webAuthn(.internalError("NFC open failed: \(sessionError)", source: .here()))
            } catch let scError as SmartCardConnectionError {
                await closeNFC(successMessage: nil)
                if Self.isTransientTransportFailure(scError) {
                    throw .webAuthn(.authenticatorNotAvailable(source: .here()))
                }
                throw .webAuthn(.internalError("NFC open failed: \(scError)", source: .here()))
            } catch {
                await closeNFC(successMessage: nil)
                if Task.isCancelled { throw FidoUI.Error.cancelled }
                throw .webAuthn(.internalError("NFC open failed: \(error)", source: .here()))
            }
        }

        func closeNFC(successMessage: String?) async {
            guard let conn = nfcConnection else { return }
            nfcConnection = nil
            if let message = successMessage {
                await conn.close(message: message)
            } else {
                await conn.close(error: nil)
            }
        }
        #endif

        // MARK: - Loop

        private func runLoop() async {
            while !Task.isCancelled, !isShutdown {
                do {
                    try await openWiredOrHID()
                    guard !Task.isCancelled, !isShutdown else { return }
                    if let wired = current {
                        _ = await wired.connection.waitUntilClosed()
                        setCurrent(nil)
                    }
                } catch is CancellationError {
                    return
                } catch {
                    guard !Task.isCancelled, !isShutdown else { return }
                    fidoLog("Transport", "open failed: \(error)")
                    try? await Task.sleep(for: Self.pollInterval)
                }
            }
        }

        // MARK: - Open

        private func openWiredOrHID() async throws {
            guard !Task.isCancelled, !isShutdown else { throw CancellationError() }

            let connection = try await wiredDriver.connect()
            let opening = Opening(id: UUID(), connection: connection)
            guard !Task.isCancelled, !isShutdown else {
                await connection.close(error: nil)
                throw CancellationError()
            }
            openingConnection = opening

            do {
                let session = try await wiredDriver.makeSession(connection)
                // cancel()/stopWiredLoop() may run while session setup awaits
                // the authenticator. Publish only if this attempt still owns
                // the live connection after that await.
                guard
                    !Task.isCancelled,
                    !isShutdown,
                    openingConnection?.id == opening.id
                else {
                    throw CancellationError()
                }
                openingConnection = nil
                setCurrent(Wired(connection: connection, session: session))
            } catch {
                if openingConnection?.id == opening.id {
                    openingConnection = nil
                    await connection.close(error: nil)
                }
                throw error
            }
        }

        private func setCurrent(_ wired: Wired?) {
            current = wired
            drainCurrentChangeWaiters()
        }

        // MARK: - Helpers

        private static func makeActiveSession(
            client: WebAuthn.Client,
            info: CTAP2.GetInfo.Response,
            ctap: CTAP2.Session
        ) -> ActiveSession {
            ActiveSession(
                client: client,
                minPINLength: info.minPinLength.map { Int($0) } ?? 4,
                hasPin: info.options.clientPin == true,
                setPIN: { pin in try await ctap.setPin(pin) },
                changePIN: { current, new in try await ctap.changePin(from: current, to: new) }
            )
        }

        private static func makeWiredTransportDriver(
            origin: WebAuthn.Origin,
            isPublicSuffix: @escaping WebAuthn.PublicSuffixChecker
        ) -> WiredTransportDriver {
            #if os(iOS)
            let devicePresent: @Sendable () async -> Bool = {
                (try? await USBSmartCardConnection.availableDevices().isEmpty) == false
            }
            let connect: @Sendable () async throws -> any Connection = {
                try await WiredSmartCardConnection.makeConnection()
            }
            #elseif os(macOS)
            let devicePresent: @Sendable () async -> Bool = { false }
            let connect: @Sendable () async throws -> any Connection = {
                try await HIDFIDOConnection()
            }
            #endif
            let makeSession: @Sendable (any Connection) async throws -> ActiveSession = { connection in
                let ctap: CTAP2.Session
                if let smartCard = connection as? any SmartCardConnection {
                    ctap = try await CTAP2.Session.makeSession(connection: smartCard)
                } else if let fido = connection as? any FIDOConnection {
                    ctap = try await CTAP2.Session.makeSession(connection: fido)
                } else {
                    throw SmartCardConnectionError.unsupported
                }
                let info = try await ctap.getInfo()
                let client = WebAuthn.Client(session: ctap, origin: origin, isPublicSuffix: isPublicSuffix)
                return Self.makeActiveSession(client: client, info: info, ctap: ctap)
            }
            return WiredTransportDriver(connect: connect, makeSession: makeSession, devicePresent: devicePresent)
        }

        #if os(iOS)
        /// Report NFC connection failures separately from CTAP errors.
        private static func isTransientTransportFailure(_ error: any Swift.Error) -> Bool {
            if let smartCardError = error as? SmartCardConnectionError {
                switch smartCardError {
                case .connectionLost, .busy, .noDevicesFound, .transmitFailed,
                    .setupFailed, .pollingFailed:
                    return true
                default:
                    return false
                }
            }
            if let sessionError = error as? CTAP2.SessionError {
                switch sessionError {
                case .connectionError(let inner, _):
                    return isTransientTransportFailure(inner)
                default:
                    return false
                }
            }
            return false
        }
        #endif

        // MARK: - Held wired/HID record

        private struct Wired {
            let connection: any Connection
            let session: ActiveSession
        }

        private struct Opening {
            let id: UUID
            let connection: any Connection
        }
    }
}
