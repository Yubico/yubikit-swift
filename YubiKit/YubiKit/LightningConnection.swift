//
//  File.swift
//  
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation

public class LightningConnection: Connection, InternalConnection {
     
    private static var connection: LightningConnection?
    internal var session: Session?
    var closingError: Error?
    private let closingSemaphore = DispatchSemaphore(value: 0)

    private init() {
        Self.connection = self
    }

    func sendAPDU() async throws -> Result<Data, Error> {
        return .failure("not implemented")
    }
    
    public func connectionDidClose() async throws -> Error? {
        await Task.sleep(1_000_000_000 * 10)
        close(nil)
        closingSemaphore.wait()
        return closingError
    }
    
    // Starts NFC and wait for a connection
    public static func connection() async throws -> Self {

        if let connection = self.connection {
            print("reuse Lightning connection")
            return connection as! Self
        }

        print("create new Lightning connection")
        let connection = LightningConnection()
        await Task.sleep(1_000_000_000 * 2)

        return connection as! Self
    }
    
    public func close(_: Result<Error, String>? = nil) {
        print("Closing Lightning Connection")
        self.closingError = nil
        self.closingSemaphore.signal()
        Self.connection = nil
    }

    
}
