//
//  DeviceConfig.swift
//  YubiKit
//
//  Created by Jens Utbult on 2023-01-31.
//

import Foundation

public struct DeviceConfig {
    public let autoEjectTimeout: TimeInterval
    public let challengeResponseTimeout: TimeInterval
    public let deviceFlags: UInt
    public let enabledCapabilities: [DeviceTransport: UInt]
    
    public func isApplicationEnabled(_ application: ApplicationType, overTransport transport: DeviceTransport) -> Bool {
        guard let mask = enabledCapabilities[transport] else { return false }
        return (mask & application.rawValue) == application.rawValue
    }
    
    public func deviceConfigWithEnabled(_ enabled: Bool, application: ApplicationType, overTransport transport: DeviceTransport) -> DeviceConfig? {
        
        guard let oldMask = enabledCapabilities[transport] else {
            return nil
        }
        let newMask = enabled ? oldMask | application.rawValue : oldMask & ~application.rawValue
        var newEnabledCapabilities = enabledCapabilities
        newEnabledCapabilities[transport] = newMask
        
        return DeviceConfig(autoEjectTimeout: autoEjectTimeout,
                            challengeResponseTimeout: challengeResponseTimeout,
                            deviceFlags: deviceFlags,
                            enabledCapabilities: newEnabledCapabilities)
    }
}
