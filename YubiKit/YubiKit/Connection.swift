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

import Foundation

/// An interface defining a physical connection to a YubiKey.
///
/// Use a connection to create a ``Session``. The connection can also be used for sending raw ``APDU``'s to the YubiKey.
///
/// Protocol implemented in ``LightningConnection``, ``NFCConnection`` and ``SmartCardConnection``.

public protocol Connection: AnyObject {
    
    /// Create a new Connection to the YubiKey.
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
    static func connection() async throws -> Connection
    
    /// Close the current Connection.
    ///
    /// This closes the connection sending the optional error to the ``connectionDidClose()`` method.
    func close(error: Error?) async
    
    /// Wait for the connection to close.
    /// 
    /// This method will wait until the connection closes. If the connection was closed due to an error said
    /// error will be returned.
    func connectionDidClose() async -> Error?
    
    /// Send an APDU to the Connection.
    ///
    /// This will send the APDU to the YubiKey using the Connection. Commands returning data to big
    /// to be handled by a single read operation will be handled automatically by the SDK and the
    /// complete result will be returned by the function. Only operations returning a 0x9100 status
    /// code will return data. Operations returning a 0x61XX (more data) status code will be handled
    /// by the SDK until they finish with a 0x9100 or an error. For all other status codes a ResponseError
    /// wrapping the status code will be thrown.
    @discardableResult
    func send(apdu: APDU) async throws -> Data
}

internal protocol InternalConnection {
    
    func session() async -> Session?
    func setSession(_ session: Session?) async
    
    // The internal version of the send() function returns a Response instead of Data. The reason for this is
    // to handle reads of large chunks of data that will be split into multiple reads. If the result is
    // to large for a single read that is signaled by sw1 being 0x61. The Response struct will return both
    // the data and sw1 and sw2. sendRecursive() in Connection+Extensions will look at the sw1 code and if
    // it indicates there's more data to read, it will call itself recursivly to retrieve the next chunk of data.
    func send(apdu: APDU) async throws -> Response
}

extension InternalConnection {
    func internalSession() async -> InternalSession? {
        let internalSession = await session()
        return internalSession as? InternalSession
    }
}

/// Connection Errors.
public enum ConnectionError: Error {
    /// No current connection.
    case noConnection
    /// Unexpected result returned from YubiKey.
    case unexpectedResult
    /// YubiKey did not return any data.
    case missingResult
    /// Awaiting call to connect() was cancelled.
    case cancelled
    /// Connection was closed.
    case closed
}

/// A ResponseError containing the status code.
public struct ResponseError: Error {
    /// Status code of the response.
    public let responseStatus: ResponseStatus
}



