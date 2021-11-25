//
//  File.swift
//  
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation

public final class LightningConnection: Connection, InternalConnection {
     
    private static var connection: LightningConnection?
    internal var session: Session?
    var closingError: Error?
    
    private static var keyInserted = false
    private var connectionClosed = false

    private init() {
        Self.connection = self
    }
    
    public static func simulateYubiKey(inserted: Bool) {
        if inserted {
            print("Insert yubikey\n---------------------------------")
            Self.keyInserted = true
        } else {
            print("Remove yubikey\n---------------------------------")
            Self.connection?.close(nil)
        }
    }

    func sendAPDU() async throws -> Result<Data, Error> {
        return .failure("not implemented")
    }
    
    public func connectionDidClose() async throws -> Error? {
        print("await lightning connectionDidClose()")
        while !connectionClosed {
            await Task.sleep(1_000_000_000 * UInt64(0.2))
        }
        return self.closingError
    }
    
    // Starts lightning and wait for a connection
    public static func connection() async throws -> Self {
        print("await lightning connection()")
        while !keyInserted {
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
    
    public func close(_: Result<Error, String>? = nil) {
//        Task.detached(priority: .background, operation: { () -> Void in
            print("Closing Lightning Connection")
            //self.session?.end(result: nil, closingConnection: false)
            self.closingError = nil
            connectionClosed = true
//            let semaphore = self.closingSemaphore.signal()
//            print(semaphore)
//            await Task.yield()
//            await Task.sleep(1_000_000_000 * UInt64(0.5))
            Self.connection = nil
            Self.keyInserted = false

//        print(Self.connection)
//        })
    }
    
    deinit {
        print("deinit LightningConnection")
    }

    
}
