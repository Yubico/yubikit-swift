//
//  Connection.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-16.
//

import Foundation

/// An interface defining a physical connection to a YubiKey.
///
/// Use a connection to create a ``Session``. The connection can also be used for sending raw ``APDU``'s to the YubiKey.
///
/// Protocol implemented in ``LightningConnection``, ``NFCConnection`` and ``SmartCardConnection``.

public protocol Connection: AnyObject {
    
    /// Create a new Connection
    ///
    /// Call this method to get a connection to a YubiKey. The method will wait
    /// until a connection to a YubiKey has been established and then return it.
    /// 
    /// If the method is called a second time while already waiting for a connection
    /// the first call to connection() will be cancelled.
    ///
    /// If a connection has been established and this method is called again the
    /// first connection will be closed and ``connectionDidClose()`` will return for
    /// the previous connection.
    ///
    static func connection() async throws -> Connection
    
    /// Close the current Connection.
    ///
    /// This closes the connection sending the optional error to the ``connectionDidClose()`` method.
    func close(error: Error?) async
    
    /// This method will wait until the connection closes. If the connection was closed due to an error said
    /// error will be returned.
    func connectionDidClose() async -> Error?
    
    /// Send a APDU to the Connection. Commands that need multiple reads from the YubiKey will
    /// be handled automatically and returning a Response only when all data has been read from the
    /// YubiKey.
    func send(apdu: APDU) async throws -> Response // TODO: this should probably only return the Data since the code will always be 0x9100
}

internal protocol InternalConnection {
    func session() async -> Session?
    func setSession(_ session: Session?) async
}

extension InternalConnection {
    func internalSession() async -> InternalSession? {
        let internalSession = await session()
        return internalSession as? InternalSession
    }
}

