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

/// Describes the configuration of a YubiKey which can be altered via the Management application.
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
