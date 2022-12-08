//
//  File.swift
//  
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation

extension Double {
    var nanoSecond: UInt64 {
        return UInt64(self / 1_000_000_000.0)
    }
}

#if os(iOS)
public final class LightningConnection: Connection, InternalConnection {

    let queue = DispatchQueue(label: "com.yubico.LightningConnection")

    @MainActor private static var connectionContinuations = [CheckedContinuation<Connection, Error>]()
    @MainActor private static var closingContinuations = [CheckedContinuation<Error?, Never>]()
    
    private static var connection: LightningConnection?
    internal var session: Session?
    var closingError: Error?
    
//    private static var keyInserted = false
    private var connectionClosed = false

    private init() {
        Self.connection = self
    }
    
    @MainActor public static func simulateYubiKey(inserted: Bool) async {
        if inserted {
            print("Insert yubikey\n---------------------------------")
            let connection = LightningConnection()
            LightningConnection.connection = connection
            connectionContinuations.forEach { continuation in
                continuation.resume(returning: connection)
            }
            connectionContinuations.removeAll()
        } else {
            print("Remove yubikey\n---------------------------------")
            await Self.connection?.close()
        }
    }

    public func send(apdu: APDU) async throws -> Response {
        throw("not implemented")
    }
    
    public func connectionDidClose() async -> Error? {
        print("await lightning connectionDidClose()")
        while !connectionClosed {
            do {
                try Task.checkCancellation()
            } catch {
                return error
            }
            try! await Task.sleep(nanoseconds: 0.2.nanoSecond)
//            await Task.sleep(1_000_000_000 * UInt64(0.2))
        }
        return self.closingError
    }
    
    // Starts lightning and wait for a connection
    @MainActor public static func connection() async throws -> Connection {
        print("await lightning connection()")
        if let connection = connection {
            print("reuse Lightning connection")
            return connection
        } else {
            return try await withCheckedThrowingContinuation { continuation in
                LightningConnection.connectionContinuations.append(continuation)
            }
        }
    }
    
    public func close(result: Result<String, Error>? = nil) async {
        print("Closing Lightning Connection")
        await LightningConnection.closingContinuations.forEach { continuation in
            continuation.resume(returning: nil)
        }
        LightningConnection.connection = nil
        await self.session?.end(withConnectionStatus: .leaveOpen)
        connectionClosed = true
    }
    
    deinit {
        print("deinit LightningConnection")
    }

    
}
#endif
