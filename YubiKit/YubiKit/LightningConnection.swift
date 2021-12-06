//
//  File.swift
//  
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation

public final class LightningConnection: Connection, InternalConnection {

    public var smartCardInterface: SmartCardInterface
    private static var connection: LightningConnection?
    internal var session: Session?
    var closingError: Error?
    
    private static var keyInserted = false
    private var connectionClosed = false

    private init() {
        smartCardInterface = SmartCardInterface()
        Self.connection = self
    }
    
    public static func simulateYubiKey(inserted: Bool) async {
        if inserted {
            print("Insert yubikey\n---------------------------------")
            Self.keyInserted = true
        } else {
            print("Remove yubikey\n---------------------------------")
            await Self.connection?.close(nil)
        }
    }

    func sendAPDU() async throws -> Result<Data, Error> {
        return .failure("not implemented")
    }
    
    public func connectionDidClose() async throws -> Error? {
        print("await lightning connectionDidClose()")
        while !connectionClosed {
            try Task.checkCancellation()
            await Task.sleep(1_000_000_000 * UInt64(0.2))
        }
        return self.closingError
    }
    
    // Starts lightning and wait for a connection
    public static func connection() async throws -> Self {
        print("await lightning connection()")
        while !keyInserted {
            try Task.checkCancellation()
            await Task.sleep(1_000_000_000 * UInt64(0.2))
        }
        if let connection = self.connection {
            print("reuse Lightning connection")
            return connection as! Self
        }
        print("create new Lightning connection")
        let connection = LightningConnection()
        return connection as! Self
    }
    
    public func close(_: Result<Error, String>? = nil) async {
        print("Closing Lightning Connection")
        await self.session?.end(result: nil, closingConnection: false)
        self.closingError = nil
        connectionClosed = true
        Self.connection = nil
        Self.keyInserted = false
    }
    
    deinit {
        print("deinit LightningConnection")
    }

    
}
