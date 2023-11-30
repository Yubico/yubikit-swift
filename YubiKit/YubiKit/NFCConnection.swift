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
import CoreNFC
import OSLog

/// A NFC connection to the YubiKey.
///
/// The  NFCConnection is short lived and should be closed as soon as the commands sent to the YubiKey have finished processing. It is up to the user of
/// the connection to close it when it no longer is needed. As long as the connection is open the NFC modal will cover the lower part of the iPhone screen.
/// In addition to the ``close(error:)`` method defined in the Connection protocol the NFCConnection has an additional ``close(message:)``
/// method that will close the connection and set the alertMessage of the NFC alert to the provided message.
///
/// > Note: NFC is only supported on iPhones from iPhone 6 and forward. It will not work on iPads since there's no NFC chip in these devices.
@available(iOS 16.0, *)
public final actor NFCConnection: Connection, InternalConnection {
    
    private static let manager = NFCConnectionManager()
    
    private weak var _session: Session?
    func session() async -> Session? {
        return _session
    }
    func setSession(_ session: Session?) async {
        _session =  session
    }
    
    private var tagReaderSession: TagReaderSession?
    private var tag: NFCISO7816Tag? { tagReaderSession?.tag }
    private var closingContinuations = [CheckedContinuation<Error?, Never>]()
    private var closingHandler: ((Result<String, Error>?) -> Void)?
    
    private init() { }
    
    fileprivate init(tagReaderSession: TagReaderSession, closingHandler handler: @escaping (Result<String, Error>?) -> Void) {
        self.tagReaderSession = tagReaderSession
        self.closingHandler = handler
    }
    
    public static func connection() async throws -> Connection {
        Logger.nfc.debug(#function)
        return try await manager.connection(alertMessage: nil)
    }
    
    /// The same function as ``connection()`` but with the option to set a message that will be displayed to the
    /// user in the iOS NFC alert.'
    public static func connection(alertMessage message: String?) async throws -> Connection {
        Logger.nfc.debug(#function)
        return try await manager.connection(alertMessage: message)
    }
    
    /// Before creating a new NFCConnection you can supply a string that will be displayed to the user in the iOS NFC alert. Use this
    /// to inform the user what the purpose of scanning the YubiKey is. For example: "Scan YubiKey to calculate OATH accounts.".
    public nonisolated func setAlertMessage(_ message: String) {
        Logger.nfc.debug(#function)
        Task {
            await tagReaderSession?.session.alertMessage = message
        }
    }
    
    public func close(error: Error?) async {
        Logger.nfc.debug(#function)
        if let error {
            await close(result: .failure(error))
        } else {
            await close(result: nil)
        }
    }
    
    /// NFCConnection can be closed with an optional message in addition to the ``Connection/close(error:)`` method defined in the Connection protocol.
    /// The message will be displayed on the iOS NFC alert when it dismisses.
    public func close(message: String?) async {
        Logger.nfc.debug(#function)
        if let message {
            await close(result: .success(message))
        } else {
            await close(result: nil)
        }
    }
    
    public func connectionDidClose() async -> Error? {
        if tag == nil {
            return nil
        }
        return await withCheckedContinuation { continuation in
            closingContinuations.append(continuation)
        }
    }
    
    internal func send(apdu: APDU) async throws -> Response {
        guard let tag else { throw "No NFC tag" }
        guard let apdu = apdu.nfcIso7816Apdu else { throw "Malformed APDU data" }
        let result: (Data, UInt8, UInt8) = try await tag.sendCommand(apdu: apdu)
        return Response(data: result.0, sw1: result.1, sw2: result.2)
    }
    
    private func close(result: Result<String, Error>?) async {
        closingHandler?(result)
        tagReaderSession = nil
        closingContinuations.forEach { continuation in
            continuation.resume(returning: result?.error)
        }
        closingContinuations.removeAll()
    }
    
    deinit {
        Logger.nfc.debug("deinit")
    }
}


fileprivate actor NFCConnectionManager {
    
    let nfcWrapper = NFCTagWrapper()
    var currentConnection: NFCConnection?
    
    var connectionTask: Task<NFCConnection, Error>?
    func connection(alertMessage message: String?) async throws -> NFCConnection {
        let task = Task { [connectionTask] in
            if let connectionTask {
                Logger.smartCard.debug("A call to connection() is already awaiting a connection, cancel it before proceeding.")
                connectionTask.cancel()
            }
            return try await self._connection(alertMessage: message)
        }
        connectionTask = task
        let value = try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
        Logger.nfc.debug("returned: \(String(describing: value))")
        return value
    }
    
    // Only allow one connect() at a time
    private func _connection(alertMessage message: String?) async throws -> NFCConnection {
        
        if let currentConnection {
            await currentConnection.close(error: nil)
            self.currentConnection = nil
        }
        
        return try await withTaskCancellationHandler {
            return try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else {
                    continuation.resume(throwing: CancellationError())
                    return
                }
                nfcWrapper.connection(alertMessage: message) { result in
                    switch result {
                    case .success(let tagReaderSession):
                        let connection = NFCConnection(tagReaderSession: tagReaderSession, closingHandler: { [weak self] result in
                            self?.nfcWrapper.endSession(result: result)
                        })
                        self.currentConnection = connection
                        continuation.resume(returning: connection)
                    case .failure(let error):
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            nfcWrapper.endSession(result: nil)
        }
    }
    
    func didDisconnect() async -> Error? {
        return await withCheckedContinuation { (continuation: CheckedContinuation<Error?, Never>) in // try to remove variable definition in the future
            nfcWrapper.connectionDidClose { error in
                continuation.resume(returning: error)
            }
        }
    }
}

fileprivate struct TagReaderSession {
    let session: NFCTagReaderSession
    let tag: NFCISO7816Tag
}

fileprivate class NFCTagWrapper: NSObject, NFCTagReaderSessionDelegate {
     
    private var tagSession: NFCTagReaderSession?
    private let queue = DispatchQueue(label: "com.yubico.nfc-connection", qos: .background)
    
    enum State {
        case ready, scanning, connected(TagReaderSession)
    }
    private var state = State.ready
    
    private var connectingHandler: ((Result<TagReaderSession, Error>) -> Void)?
    private var closingHandler: ((Error?) -> Void)?
    
    internal func connection(alertMessage message: String?, completion handler: @escaping (Result<TagReaderSession, Error>) -> Void) {
        queue.async {
            self.closingHandler?("Closed by new call to connection()")
            self.closingHandler = nil
            self.connectingHandler?(.failure("Cancelled by new call to connection()"))
            self.connectingHandler = handler
            
            switch self.state {
            case .ready:
                self.tagSession = NFCTagReaderSession(pollingOption: .iso14443, delegate: self)
                if let message {
                    self.tagSession?.alertMessage = message
                }
                self.tagSession?.begin()
                self.state = .scanning
            case .scanning:
                return
            case .connected(let tagReaderSession):
                self.connectingHandler?(.success(tagReaderSession))
                self.connectingHandler = nil
            }
        }
    }
    
    internal func connectionDidClose(completion handler: @escaping (Error?) -> Void) {
        queue.async {
            assert(self.closingHandler == nil, "Closing completion already registered.")
            self.closingHandler = handler
        }
    }
    
    func endSession(result: Result<String, Error>?) {
        queue.async {
            if let result {
                switch result {
                case .success(let message):
                    self.tagSession?.alertMessage = message
                    self.tagSession?.invalidate()
                case .failure(let error):
                    self.tagSession?.invalidate(errorMessage: error.localizedDescription)
                }
            } else {
                self.tagSession?.invalidate()
            }
            self.tagSession = nil
            self.state = .ready
        }
    }
    
    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        queue.async {
            self.state = .scanning
            self.tagSession = session
        }
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        queue.async {
            self.connectingHandler?(.failure(error))
            self.connectingHandler = nil
            self.closingHandler?(error)
            self.closingHandler = nil
            self.state = .ready
        }
    }
    
    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        queue.async {
            guard let tag = tags.first else { return }
            self.tagSession?.connect(to: tag) { error in
                if let error {
                    Logger.nfc.debug("Failed connecting to tag with error: \(error)")
                    self.connectingHandler?(.failure(error))
                    self.connectingHandler = nil
                    return
                }
                if case let NFCTag.iso7816(tag) = tag {
                    Logger.nfc.debug("Connected to tag: \(String(describing: tag))")
                    let session = TagReaderSession(session: self.tagSession!, tag: tag)
                    self.state = .connected(session)
                    self.connectingHandler?(.success(session))
                } else {
                    Logger.nfc.debug("Failed connecting to \(String(describing: tag)) since it's not a iso7816 tag.")
                    self.connectingHandler?(.failure("Not an iso7816 tag!"))
                }
                self.connectingHandler = nil
            }
        }
    }
}

extension Connection {
    /// Returns a NFCConnection if the connection is a NFCConnection. This is useful since NFCConnections need to be
    /// closed as soon as you are done sending commands to them while wired connections are usually kept alive.
    public var nfcConnection: NFCConnection? {
        self as? NFCConnection
    }
}

extension NFCTagWrapper.State: Equatable {
    fileprivate static func == (lhs: NFCTagWrapper.State, rhs: NFCTagWrapper.State) -> Bool {
        switch (lhs, rhs) {
        case (.ready, .ready), (.scanning, .scanning):
            return true
        case (.connected(let rhsTag), .connected(let lhsTag)):
            return rhsTag.tag.identifier == lhsTag.tag.identifier
        default:
            return false
        }
    }
}

extension APDU {
    var nfcIso7816Apdu: NFCISO7816APDU? {
        return NFCISO7816APDU(data: self.data)
    }
}

extension Result {
    var error: Error? {
        switch self {
        case .failure(let error):
            return error
        default:
            return nil
        }
    }
}

#endif
