import Foundation
import YubiKit

extension FidoUI {

    /// Production transport. Maintains a wired/HID session via a
    /// background loop; opens NFC sessions one-shot on demand. Built
    /// fresh per ceremony.
    actor TransportController: TransportControllerProtocol {

        private let origin: WebAuthn.Origin
        private let isPublicSuffix: WebAuthn.PublicSuffixChecker

        /// Backoff between failed open attempts. The OS doesn't surface
        /// "device became available" as an awaitable event, so hardware
        /// enumeration polls.
        private static let pollInterval: Duration = .milliseconds(500)

        private var current: Wired?
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

        init(origin: WebAuthn.Origin, isPublicSuffix: @escaping WebAuthn.PublicSuffixChecker) {
            self.origin = origin
            self.isPublicSuffix = isPublicSuffix
        }

        // MARK: - Lifecycle

        func start() {
            guard loopTask == nil else { return }
            loopTask = Task { [weak self] in
                await self?.runLoop()
            }
        }

        func cancel() async {
            isShutdown = true
            loopTask?.cancel()
            loopTask = nil
            let wired = current
            setCurrent(nil)
            if let wired { await wired.connection.close(error: nil) }
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
            isShutdown = true
            setCurrent(nil)
            if let wired { await wired.connection.close(error: nil) }
        }

        // MARK: - Wired API

        func wired() -> ActiveSession? {
            current.map { Self.makeActiveSession(client: $0.client, info: $0.info, ctap: $0.session) }
        }

        func isWiredAvailable() -> Bool {
            current != nil
        }

        func awaitWired() async throws(FidoUI.Error) -> ActiveSession {
            while true {
                if Task.isCancelled || isShutdown { throw .cancelled }
                if let wired = current {
                    return Self.makeActiveSession(
                        client: wired.client,
                        info: wired.info,
                        ctap: wired.session
                    )
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
                let ctap = try await CTAP2.Session.makeSession(connection: conn)
                let info = try await ctap.getInfo()
                let client = WebAuthn.Client(
                    session: ctap,
                    origin: origin,
                    isPublicSuffix: isPublicSuffix
                )
                nfcConnection = conn
                return Self.makeActiveSession(client: client, info: info, ctap: ctap)
            } catch is CancellationError {
                throw .cancelled
            } catch SmartCardConnectionError.cancelled, SmartCardConnectionError.cancelledByUser {
                throw .cancelled
            } catch let scError as SmartCardConnectionError {
                if Self.isTransientTransportFailure(scError) {
                    throw .webAuthn(.authenticatorNotAvailable(source: .here()))
                }
                throw .webAuthn(.internalError("NFC open failed: \(scError)", source: .here()))
            } catch {
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
            while !Task.isCancelled {
                do {
                    try await openWiredOrHID()
                    if let wired = current {
                        _ = await wired.connection.waitUntilClosed()
                        setCurrent(nil)
                    }
                } catch is CancellationError {
                    return
                } catch {
                    fidoLog("Transport", "open failed: \(error)")
                    try? await Task.sleep(for: Self.pollInterval)
                }
            }
        }

        // MARK: - Open

        private func openWiredOrHID() async throws {
            #if os(iOS)
            let conn = try await WiredSmartCardConnection.makeConnection()
            do {
                let ctap = try await CTAP2.Session.makeSession(connection: conn)
                try await assignWired(connection: conn, ctap: ctap)
            } catch {
                await conn.close(error: nil)
                throw error
            }
            #elseif os(macOS)
            let conn = try await HIDFIDOConnection()
            do {
                let ctap = try await CTAP2.Session.makeSession(connection: conn)
                try await assignWired(connection: conn, ctap: ctap)
            } catch {
                await conn.close(error: nil)
                throw error
            }
            #endif
        }

        private func assignWired(
            connection: any Connection,
            ctap: CTAP2.Session
        ) async throws {
            let info = try await ctap.getInfo()
            let client = WebAuthn.Client(
                session: ctap,
                origin: origin,
                isPublicSuffix: isPublicSuffix
            )
            setCurrent(
                Wired(connection: connection, session: ctap, client: client, info: info)
            )
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

        /// Maps transient transport drops to `.authenticatorNotAvailable`
        /// so the runCeremony catch can reconnect rather than surface fatal.
        static func isTransientTransportFailure(_ error: any Swift.Error) -> Bool {
            if let smartCardError = error as? SmartCardConnectionError {
                switch smartCardError {
                case .connectionLost, .busy, .noDevicesFound, .transmitFailed,
                    .setupFailed, .pollingFailed:
                    return true
                default:
                    return false
                }
            }
            if let fidoError = error as? FIDOConnectionError {
                switch fidoError {
                case .noDevicesFound, .connectionLost, .busy, .transmitFailed, .receiveFailed:
                    return true
                default:
                    return false
                }
            }
            if let sessionError = error as? CTAP2.SessionError {
                switch sessionError {
                case .fidoConnectionError(let inner, _):
                    return isTransientTransportFailure(inner)
                case .connectionError(let inner, _):
                    return isTransientTransportFailure(inner)
                default:
                    return false
                }
            }
            return false
        }

        // MARK: - Held wired/HID record

        private struct Wired {
            let connection: any Connection
            let session: CTAP2.Session
            let client: WebAuthn.Client
            let info: CTAP2.GetInfo.Response
        }
    }
}
