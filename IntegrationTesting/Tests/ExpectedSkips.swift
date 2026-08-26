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

/// Scenarios known not to run on the default TwinKit profile.
///
/// A skip outside this list fails the run. Without that, a scenario can quietly stop executing and
/// the suite stays green — the count of test cases does not change, because a skip and a pass are
/// indistinguishable to the test framework. Adding an entry here is therefore a deliberate,
/// reviewable act rather than something that happens by omission.
///
/// Entries cover both transports, so a scenario that only skips over NFC still appears once. The
/// grouping comments are the reason reported at the time of capture; they are documentation, not
/// matched at runtime, since one scenario can skip for different reasons on different transports.
enum ExpectedSkips {

    /// Enforcement applies to the default profile only. Other profiles legitimately skip a
    /// different set — FIPS scenarios run on `5-fips` and not elsewhere, and vice versa — and
    /// baselining every profile is only worth doing once they are all in regular rotation.
    static var isEnforced: Bool {
        switch ProcessInfo.processInfo.environment["YUBIKIT_ENABLE_TWINKIT"] {
        case "1", "5-nfc": return true
        default: return false
        }
    }

    static func allows(_ scenarioID: String) -> Bool {
        defaultProfile.contains(scenarioID)
    }

    private static let defaultProfile: Set<String> = [
        // requires real hardware
        "CTAP2.Credentials.cancelMakeCredential",
        "Connection.SmartCard.cancellation",
        "Connection.SmartCard.serial",
        "PIV.Attestation.ed25519",
        "PIV.Attestation.rsa",
        "PIV.Attestation.x25519",
        "PIV.KeyManagement.generateKeyRequiresAuth",
        "PIV.KeyManagement.putCertificateRequiresAuth",
        "PIV.KeyManagement.putKeyRequiresAuth",
        "PIV.Operations.pinPolicyOnce",

        // previewSign not supported
        "CTAP2.PreviewSign.generateAndSign",
        "CTAP2.PreviewSign.invalidFlags",
        "CTAP2.PreviewSign.missingParameter",
        "CTAP2.PreviewSign.unsupportedAlgorithm",
        "CTAP2.PreviewSign.upRequired",
        "CTAP2.PreviewSign.uvRequired",
        "WebAuthn.PreviewSign.generateKey",
        "WebAuthn.PreviewSign.noOutputWithoutInput",

        // requires a FIDO (HID) transport, unavailable on this backend
        "CTAPHID.Capabilities.winkSupported",
        "CTAPHID.Commands.wink",
        "CTAPHID.Errors.invalidCommand",
        "CTAPHID.Interface.getInfo",
        "CTAPHID.Interface.initialize",
        "CTAPHID.Ping.echo",
        "Connection.FIDOHID.withDevice",

        // requires a Bio (fingerprint) device
        "CTAP2.Bio.enrollRenameDelete",
        "CTAP2.Bio.makeCredentialUvToken",
        "CTAP2.Bio.sensorInfo",
        "CTAP2.Bio.uvBlocking",
        "Management.Reset.bioDeviceReset",
        "PIV.Bio.authentication",
        "PIV.Bio.verifyUvWithoutFingerprints",

        // requires a FIPS-certified device
        "OATH.Password.deleteAccessKeyRejectedOnFIPS",
        "PIV.FIPS.rejectsForbiddenKeyType.rsa1024",
        "PIV.FIPS.rejectsForbiddenKeyType.x25519",
        "PIV.FIPS.rejectsPinPolicyNever",

        // encIdentifier not supported
        "CTAP2.EncryptedFields.decryptIdentifier",
        "CTAP2.EncryptedFields.encIdentifierChanges",
        "CTAP2.EncryptedFields.persistentToken",

        // requires transport usb (device is on nfc)
        "CTAP2.Reset.factory",

        // Device doesn't enforce PIN complexity
        "CTAP2.ClientPIN.complexityV1",
        "CTAP2.ClientPIN.complexityV2",

        // Enterprise attestation not supported
        "CTAP2.Config.enableEnterpriseAttestation",
        "CTAP2.Config.enterpriseAttestationPlatform",

        // UV supported but not configured (no fingerprints enrolled)
        "CTAP2.ClientPIN.tokenUsingUvV1",
        "CTAP2.ClientPIN.tokenUsingUvV2",

        // encCredStoreState not supported
        "CTAP2.EncryptedFields.credStoreStateChanges",
        "CTAP2.EncryptedFields.decryptCredStoreState",

        // Persistent pinUvAuthToken (read-only) not supported
        "CTAP2.CredentialManagement.readOnlyPpuat",

        // hmac-secret-mc not supported
        "WebAuthn.PRF.makeCredential",

        // maxPINLength not reported
        "CTAP2.Config.setMinPinLength",

        // requires firmware ≤ 5.1.99 (device is 5.7.4)
        "CTAP2.Credentials.makeAssert.rs256",
    ]
}
