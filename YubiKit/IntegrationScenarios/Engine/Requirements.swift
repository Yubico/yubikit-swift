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
import YubiKit

/// Declarative preconditions for a scenario.
public struct Requirements: Sendable {
    public var capabilities: Set<Capability>
    public var minVersion: Version?
    /// Inclusive upper firmware bound; with `minVersion` this expresses a version range.
    public var maxVersion: Version?
    public var transports: Set<DeviceTransport>?
    public var requiresBio: Bool
    /// Forbid a Bio device.
    public var excludesBio: Bool
    /// Require a FIPS-certified device.
    public var requiresFIPS: Bool
    /// Forbid a FIPS-certified device (behavior that FIPS firmware blocks, e.g. PIN policy NEVER).
    public var excludesFIPS: Bool
    public var requiresFIDOTransport: Bool
    public var requiresLightning: Bool
    public var requiresSCP: Bool
    /// Require real silicon.
    public var requiresRealHardware: Bool

    init(
        capabilities: Set<Capability> = [],
        minVersion: Version? = nil,
        maxVersion: Version? = nil,
        transports: Set<DeviceTransport>? = nil,
        requiresBio: Bool = false,
        excludesBio: Bool = false,
        requiresFIPS: Bool = false,
        excludesFIPS: Bool = false,
        requiresFIDOTransport: Bool = false,
        requiresLightning: Bool = false,
        requiresSCP: Bool = false,
        requiresRealHardware: Bool = false
    ) {
        self.capabilities = capabilities
        self.minVersion = minVersion
        self.maxVersion = maxVersion
        self.transports = transports
        self.requiresBio = requiresBio
        self.excludesBio = excludesBio
        self.requiresFIPS = requiresFIPS
        self.excludesFIPS = excludesFIPS
        self.requiresFIDOTransport = requiresFIDOTransport
        self.requiresLightning = requiresLightning
        self.requiresSCP = requiresSCP
        self.requiresRealHardware = requiresRealHardware
    }

    /// Whether these requirements need `DeviceInfo`.
    var needsDeviceInfo: Bool {
        !capabilities.isEmpty || minVersion != nil || maxVersion != nil
            || requiresBio || excludesBio || requiresFIPS || excludesFIPS
    }
}
