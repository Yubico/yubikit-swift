//
//  NFCConnection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation

public final class NFCConnection: Connection, InternalConnection {

    static var connection: NFCConnection?
    var session: Session?
    var closingError: Error?
    let closingSemaphore = DispatchSemaphore(value: 0)

    private init() {}

    func sendAPDU() async throws -> Result<Data, Error> {
        return .failure("not implemented")
    }
    
    public func connectionDidClose() async throws -> Error? {
        closingSemaphore.wait()
        return closingError
    }
    
    // Starts NFC and wait for a connection
    public static func connection() async throws -> Self {
        if let connection = self.connection {
            print("reuse NFC connection")
            return connection as! Self
        }
        print("create new NFC connection")
        Thread.sleep(forTimeInterval: 0.5)
        let connection = NFCConnection()
        self.connection = connection
        return connection as! Self
    }
    
    public func close(_: Result<Error, String>? = nil) {
        print("Closing NFC Connection")
        self.closingError = nil
        self.closingSemaphore.signal()
        Self.connection = nil
    }
}
