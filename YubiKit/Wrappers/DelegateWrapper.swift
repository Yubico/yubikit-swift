//
//  DelegateWrapper.swift
//  YubiKit
//
//  Created by Jens Utbult on 2022-12-09.
//

import Foundation

public protocol YubKitWrapperDelegate {
    func didConnect(connection: Connection)
}

public class YubiKitWrapper {
    
    public var delegate: YubKitWrapperDelegate? = nil
    var connection: Connection?
    
    public init(delegate: YubKitWrapperDelegate? = nil) {
        self.delegate = delegate
    }
    
    public func startAnyConnection() {
        ConnectionHelper.anyConnection { connection, error in
            guard let connection else { print("Handle error"); return }
            self.connection = connection
            self.delegate?.didConnect(connection: connection)
        }
    }
    
    public func stopConnection() {
        connection?.close()
        self.connection = nil
    }
}
