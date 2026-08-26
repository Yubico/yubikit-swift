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

/// Management application scenarios.
public enum ManagementScenario: CaseIterable, ScenarioSuite {

    case version
    case deviceInfo
    case timeouts
    case chaining
    case disableEnableApplication
    case lockCode
    case nfcRestricted
    case bioDeviceReset

    public var scenario: Scenario {
        switch self {
        // MARK: - Info
        case .version:
            return Scenario(
                "Management.Info.version",
                "reports a firmware version"
            ) { context in
                let session = try await context.managementSession()
                let version = await session.version
                context.expect(version.major >= 4, "expected a real firmware version, got \(version)")
            }
        case .deviceInfo:
            return Scenario(
                "Management.Info.deviceInfo",
                "getDeviceInfo round-trips with a serial number"
            ) { context in
                let session = try await context.managementSession()
                let info = try await session.getDeviceInfo()
                context.expectEqual(info.version, await session.version, "DeviceInfo.version matches session")
                context.expect(info.serialNumber > 0, "serial number should be greater than 0")
            }
        // MARK: - Configuration
        case .timeouts:
            return Scenario(
                "Management.Config.timeouts",
                "updateDeviceConfig round-trips auto-eject / challenge-response timeouts",
                requirements: Requirements(minVersion: Version("5.0.0"))
            ) { context in
                let session = try await context.managementSession()
                let config = try await session.getDeviceInfo().config
                    .with(autoEjectTimeout: 320.0, challengeResponseTimeout: 135.0)
                try await session.updateDeviceConfig(config, reboot: false)
                let info = try await session.getDeviceInfo()
                context.expect(info.config.challengeResponseTimeout == 135.0, "challengeResponseTimeout == 135")
                context.expect(info.config.autoEjectTimeout == 320.0, "autoEjectTimeout == 320")
            }
        case .chaining:
            // (test_disable_oath / test_disable_piv / test_disable_openpgp / test_disable_fido2): each disables
            // an application then re-reads config to confirm it is gone (here chained in one updateDeviceConfig).
            return Scenario(
                "Management.Config.chaining",
                "chained enable/disable across applications round-trips",
                requirements: Requirements(minVersion: Version("5.0.0"))
            ) { context in
                let session = try await context.managementSession()
                let transport = context.deviceTransport
                let info = try await session.getDeviceInfo()
                let initialConfig = info.config

                let chained = info.config
                    .disable(application: .oath, over: transport)
                    .enable(application: .piv, over: transport)
                    .disable(application: .openPGP, over: transport)
                    .enable(application: .fido2, over: transport)
                try await session.updateDeviceConfig(chained, reboot: false)
                // Restore via teardown so a failure below can't leave applications disabled.
                await context.addTeardown { try await session.updateDeviceConfig(initialConfig, reboot: false) }
                let updated = try await session.getDeviceInfo()

                if info.isApplicationSupported(.oath, over: transport) {
                    context.expect(!updated.config.isApplicationEnabled(.oath, over: transport), "OATH disabled")
                }
                if info.isApplicationSupported(.piv, over: transport) {
                    context.expect(updated.config.isApplicationEnabled(.piv, over: transport), "PIV enabled")
                }
                if info.isApplicationSupported(.openPGP, over: transport) {
                    context.expect(!updated.config.isApplicationEnabled(.openPGP, over: transport), "OpenPGP disabled")
                }
                if info.isApplicationSupported(.fido2, over: transport) {
                    context.expect(updated.config.isApplicationEnabled(.fido2, over: transport), "FIDO2 enabled")
                }
            }
        case .disableEnableApplication:
            // `config usb --list`); re-enable corresponds to that suite's enable_all fixture (`config usb --enable-all`).
            // Goes further than the CLI test by also asserting the applet can no longer be selected while disabled.
            return Scenario(
                "Management.Config.disableEnableApplication",
                "a disabled application can no longer be selected (then re-enabled)",
                requirements: Requirements(capabilities: [.oath], minVersion: Version("5.0.0"))
            ) { context in
                let connection = try await context.smartCardConnection()
                // Build sessions directly (multiple selects on one connection), so thread the run's
                // secure-channel params — else this runs plaintext even when the run forces SCP.
                let scp = try await context.scpKeyParams()
                let session = try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
                let transport = context.deviceTransport
                let initialConfig = try await session.getDeviceInfo().config

                try await session.updateDeviceConfig(
                    initialConfig.disable(application: .oath, over: transport),
                    reboot: false
                )
                // Restore via teardown (on a fresh session — the body selects other applets meanwhile)
                // so a mid-body failure can't leave OATH disabled for the rest of the run.
                await context.addTeardown {
                    let mgmt = try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
                    try await mgmt.updateDeviceConfig(initialConfig, reboot: false)
                }
                let disabled = try await session.getDeviceInfo()
                context.expect(!disabled.config.isApplicationEnabled(.oath, over: transport), "OATH reported disabled")
                let oath = try? await OATHSession.makeSession(connection: connection, scpKeyParams: scp)
                context.expect(oath == nil, "OATH applet must be unselectable while disabled")

                let mgmt = try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
                try await mgmt.updateDeviceConfig(
                    initialConfig.enable(application: .oath, over: transport),
                    reboot: false
                )
                context.expect(
                    try await mgmt.getDeviceInfo().config.isApplicationEnabled(.oath, over: transport),
                    "OATH re-enabled"
                )
            }
        case .lockCode:
            // teardown); also exercises test_set_invalid_lock_code's premise that a config change without the correct
            // lock code is rejected.
            return Scenario(
                "Management.Config.lockCode",
                "a set lock code is required to change configuration",
                requirements: Requirements(minVersion: Version("5.0.0"))
            ) { context in
                let lockCode = Data(hexString: "01020304050607080102030405060708")!
                let clearLockCode = Data(hexString: "00000000000000000000000000000000")!
                let session = try await context.managementSession()
                let config = try await session.getDeviceInfo().config

                try await session.updateDeviceConfig(config, reboot: false, newLockCode: lockCode)
                // From here the device is lock-coded — clear it via teardown so a failure below can't
                // leave the key permanently locked.
                await context.addTeardown {
                    try await session.updateDeviceConfig(
                        config,
                        reboot: false,
                        lockCode: lockCode,
                        newLockCode: clearLockCode
                    )
                }
                do {
                    try await session.updateDeviceConfig(config.disable(application: .oath, over: .usb), reboot: false)
                    context.record("config update without the lock code should have failed")
                } catch {
                    context.log("config update correctly rejected without the lock code")
                }
                try await session.updateDeviceConfig(
                    config.disable(application: .oath, over: .usb),
                    reboot: false,
                    lockCode: lockCode
                )
            }
        case .nfcRestricted:
            // "restrict NFC until next USB insertion" flag (nfcRestricted / isNFCRestricted)
            return Scenario(
                "Management.Config.nfcRestricted",
                "NFC can be restricted until next USB insertion",
                requirements: Requirements(minVersion: Version("5.7.0"))
            ) { context in
                let session = try await context.managementSession()
                let config = try await session.getDeviceInfo().config.with(nfcRestricted: true)
                try await session.updateDeviceConfig(config, reboot: false)
                let updated = try await session.getDeviceInfo()
                context.expect(updated.config.isNFCRestricted == true, "NFC should report as restricted")
            }
        // MARK: - Reset
        case .bioDeviceReset:
            return Scenario(
                "Management.Reset.bioDeviceReset",
                "device-wide reset restores the default PIV PIN (Bio MPE)",
                requirements: Requirements(capabilities: [.piv], minVersion: Version("5.6.0"), requiresBio: true)
            ) { context in
                let connection = try await context.smartCardConnection()
                // resetDevice wipes the applications but not the Security Domain, so the SCP keys survive;
                // each makeSession re-handshakes, so the post-reset sessions re-secure cleanly.
                let scp = try await context.scpKeyParams()
                let session = try await Management.Session.makeSession(connection: connection, scpKeyParams: scp)
                try await session.resetDevice()

                var piv = try await PIVSession.makeSession(connection: connection, scpKeyParams: scp)
                context.expect(try await piv.getPinMetadata().isDefault, "PIN should be default after reset")
                // New PIN must satisfy 5.7 PIN complexity (no monotonic run like "654321").
                try await piv.changePin(from: Scenario.Context.defaultPIVPin, to: "284631")
                context.expect(!(try await piv.getPinMetadata().isDefault), "PIN should be non-default after change")

                try await Management.Session.makeSession(connection: connection, scpKeyParams: scp).resetDevice()
                piv = try await PIVSession.makeSession(connection: connection, scpKeyParams: scp)
                context.expect(try await piv.getPinMetadata().isDefault, "PIN should be default again after reset")
            }
        }
    }
}
