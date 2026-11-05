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

import CryptoTokenKit
import Foundation
import Testing

@testable import YubiKit

struct DeviceInfoNamingTests {
    // Naming expectations follow yubikit Rust a42623b and Python's test_device.py.
    struct Case: Sendable, CustomStringConvertible {
        let expected: String
        var version = "5.7.0"
        var formFactor: FormFactor = .usbAKeychain
        var nfc = false
        var sky = false
        var fips = false
        var serial: UInt = 123
        var capabilities: [Capability] = [.otp, .piv, .fido2]
        var pinComplexity = false

        var description: String { expected }
        var info: DeviceInfo {
            let usb = capabilities.reduce(UInt(0)) { $0 | $1.rawValue }
            var supported: [DeviceTransport: UInt] = [.usb: usb]
            if nfc { supported[.nfc] = usb }
            return DeviceInfo(
                version: Version(version)!,
                serialNumber: serial,
                formFactor: formFactor,
                supportedCapabilities: supported,
                isFIPS: fips,
                isSKY: sky,
                pinComplexity: pinComplexity
            )
        }
    }

    // Effective make_info inputs and expected names from crates/yubikit/src/device.rs at a42623b.
    // Rust applies fixups before naming in the two inferred-SKY cases; Swift computes them in deviceName.
    @Test(
        "Rust naming fixtures",
        arguments: [
            (
                "test_neo",
                Case(
                    expected: "YubiKey NEO",
                    version: "3.5.0",
                    formFactor: .unknown,
                    nfc: true,
                    capabilities: [.otp, .oath]
                )
            ),
            (
                "test_yk4",
                Case(
                    expected: "YubiKey 4",
                    version: "4.3.7",
                    serial: 456,
                    capabilities: [.otp, .piv, .oath]
                )
            ),
            (
                "test_yk4_fips",
                Case(
                    expected: "YubiKey FIPS (4 Series)",
                    version: "4.4.5",
                    fips: true,
                    serial: 789,
                    capabilities: [.otp, .piv]
                )
            ),
            (
                "test_yk5_nfc",
                Case(
                    expected: "YubiKey 5 NFC",
                    version: "5.2.4",
                    nfc: true,
                    serial: 100,
                    capabilities: [.otp, .piv, .fido2]
                )
            ),
            (
                "test_yk5c_nano",
                Case(
                    expected: "YubiKey 5C Nano",
                    version: "5.4.3",
                    formFactor: .usbCNano,
                    serial: 200,
                    capabilities: [.otp, .piv]
                )
            ),
            (
                "test_yk5ci",
                Case(
                    expected: "YubiKey 5Ci",
                    version: "5.2.4",
                    formFactor: .usbCLightning,
                    serial: 300,
                    capabilities: [.otp, .piv]
                )
            ),
            (
                "test_security_key_nfc",
                Case(
                    expected: "Security Key NFC",
                    version: "5.2.8",
                    nfc: true,
                    sky: true,
                    serial: 0,
                    capabilities: [.u2f, .fido2]
                )
            ),
            (
                "test_bio_fido",
                Case(
                    expected: "YubiKey Bio - FIDO Edition",
                    version: "5.5.6",
                    formFactor: .usbABio,
                    serial: 400,
                    capabilities: [.u2f, .fido2]
                )
            ),
            (
                "test_bio_multi_protocol",
                Case(
                    expected: "YubiKey C Bio - Multi-protocol Edition",
                    version: "5.6.0",
                    formFactor: .usbCBio,
                    serial: 500,
                    capabilities: [.piv, .fido2]
                )
            ),
            (
                "test_preview",
                Case(
                    expected: "YubiKey Preview",
                    version: "5.0.1",
                    serial: 600,
                    capabilities: [.otp, .piv]
                )
            ),
            (
                "test_sky_enterprise",
                Case(
                    expected: "Security Key A - Enterprise Edition",
                    version: "5.4.3",
                    sky: true,
                    serial: 700,
                    capabilities: [.u2f, .fido2]
                )
            ),
            (
                "test_sky_nfc_inferred",
                Case(
                    expected: "Security Key NFC",
                    version: "5.1.2",
                    nfc: true,
                    serial: 0,
                    capabilities: [.u2f, .fido2]
                )
            ),
            (
                "test_yk5a",
                Case(
                    expected: "YubiKey 5A",
                    version: "5.2.4",
                    serial: 800,
                    capabilities: [.otp, .piv]
                )
            ),
            (
                "test_enhanced_pin",
                Case(
                    expected: "YubiKey 5C - Enhanced PIN",
                    formFactor: .usbCKeychain,
                    serial: 900,
                    capabilities: [.otp, .piv],
                    pinComplexity: true
                )
            ),
            (
                "test_sky_preview_firmware",
                Case(
                    expected: "Security Key by Yubico",
                    version: "5.0.2",
                    serial: 0,
                    capabilities: [.u2f, .fido2]
                )
            ),
            (
                "test_sky_u2f_only",
                Case(
                    expected: "FIDO U2F Security Key",
                    version: "0.0.0",
                    formFactor: .unknown,
                    sky: true,
                    serial: 0,
                    capabilities: [.u2f]
                )
            ),
        ]
    )
    func rustFixtures(sourceTest: String, testCase: Case) {
        #expect(testCase.info.deviceName == testCase.expected, "Rust: \(sourceTest)")
    }

    @Test(
        "Additional form factors and suffix precedence",
        arguments: [
            Case(expected: "YubiKey 5", formFactor: .unknown),
            Case(expected: "YubiKey 5 NFC", formFactor: .unknown, nfc: true),
            Case(expected: "YubiKey 5A FIPS", fips: true, pinComplexity: true),
            Case(expected: "Security Key NFC", nfc: true, sky: true, serial: 0, pinComplexity: true),
            Case(expected: "YubiKey Bio FIPS", formFactor: .usbABio, fips: true, capabilities: [.fido2]),
            Case(expected: "YubiKey (0.0.0)", version: "0.0.0", formFactor: .unknown),
            Case(expected: "YubiKey FIPS (4 Series)", version: "4.4.5"),
            Case(expected: "YubiKey FIPS (4 Series)", version: "4.3.7", fips: true),
            Case(expected: "YubiKey 5 NFC", version: "5.2.8", nfc: true, serial: 0, capabilities: [.u2f, .fido2]),
        ]
    )
    func names(testCase: Case) {
        #expect(testCase.info.deviceName == testCase.expected)
    }

    @Test(
        "Preview firmware boundaries",
        arguments: [
            ("5.0.0", "YubiKey Preview"), ("5.1.0", "YubiKey 5A"),
            ("5.2.0", "YubiKey Preview"), ("5.2.2", "YubiKey Preview"), ("5.2.3", "YubiKey 5A"),
            ("5.5.0", "YubiKey Preview"), ("5.5.1", "YubiKey Preview"), ("5.5.2", "YubiKey 5A"),
        ]
    )
    func preview(version: String, expected: String) {
        #expect(Case(expected: expected, version: version).info.deviceName == expected)
    }

    @Test("Rust test_device_info_parse_name fixture")
    func rustReportedNameFixture() {
        let info = DeviceInfo(
            withTlvs: [0x05: Data([6, 0, 0]), 0x01: Data([0x02, 0x3f]), 0x1b: Data("A Custom Name".utf8)],
            fallbackVersion: Version("0.0.0")!
        )
        #expect(info.reportedName == "A Custom Name")
        #expect(info.deviceName == "A Custom Name")
    }

    @Test(
        "Device-reported names are decoded strictly and take precedence",
        arguments: [
            (Data(), nil), (Data([0xc3, 0x28]), nil), (Data("Ключ 😀".utf8), "Ключ 😀"),
        ] as [(Data?, String?)]
    )
    func reportedName(data: Data?, expected: String?) {
        var tlvs: [TKTLVTag: Data] = [0x04: Data([0x83]), 0x16: Data([1])]
        tlvs[0x1b] = data
        let info = DeviceInfo(withTlvs: tlvs, fallbackVersion: Version("5.7.0")!)
        #expect(info.reportedName == expected)
        #expect(info.deviceName == (expected ?? "YubiKey 5C FIPS"))
    }

    @Test("Enabled applications and NFC restrictions do not affect the product name")
    func configurationDoesNotAffectName() {
        for enabled: UInt in [0, Capability.fido2.rawValue, 0xffff] {
            let info = DeviceInfo(
                version: Version("5.8.0")!,
                formFactor: .usbCKeychain,
                supportedCapabilities: [.usb: 0x023f, .nfc: 0x023f],
                config: DeviceConfig(enabledCapabilities: [.usb: enabled, .nfc: enabled], isNFCRestricted: true)
            )
            #expect(info.deviceName == "YubiKey 5C NFC")
        }
    }

    @Test(
        "Known incorrect NFC reports do not change product names",
        arguments: [
            Case(expected: "YubiKey 5Ci", formFactor: .usbCLightning, nfc: true),
            Case(expected: "YubiKey 5 Nano", formFactor: .usbANano, nfc: true),
            Case(expected: "YubiKey 5C Nano", formFactor: .usbCNano, nfc: true),
            Case(expected: "YubiKey 5C", version: "5.2.3", formFactor: .usbCKeychain, nfc: true),
            Case(expected: "YubiKey 5C NFC", version: "5.2.4", formFactor: .usbCKeychain, nfc: true),
            Case(expected: "Security Key A", version: "5.2.0", sky: true, serial: 0),
        ]
    )
    func transportQuirks(testCase: Case) {
        #expect(testCase.info.deviceName == testCase.expected)
    }
}
