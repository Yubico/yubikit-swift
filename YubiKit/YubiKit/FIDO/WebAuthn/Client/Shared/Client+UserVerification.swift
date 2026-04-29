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

// MARK: - User Verification

extension WebAuthn.Client {

    // MARK: - Retry Context

    // Tracks UV/PIN state across retry attempts.
    // Handles: PUAT required (upgrade discouraged→required), UV blocked (fall back to PIN).
    struct RetryContext {
        var userVerification: WebAuthn.UserVerificationPreference
        var allowUV: Bool = true

        // Returns true if error is recoverable and state was updated for retry.
        mutating func shouldRetry(for error: CTAP2.SessionError) -> Bool {
            switch error {
            case .ctapError(.puatRequired, _) where userVerification == .discouraged:
                userVerification = .required
                return true
            case .ctapError(.uvBlocked, _) where allowUV:
                allowUV = false
                return true
            default:
                return false
            }
        }
    }

    // MARK: - Token Acquisition

    // Acquires a PIN/UV auth token if required.
    //
    // PIN and UV are both one-shot. UV failures (`uvInvalid` / `uvBlocked`)
    // fall through to PIN when `clientPin` is configured, otherwise throw
    // `.uvBlocked`. PIN failures (`pinInvalid`) throw `.pinRejected` with
    // the remaining retry count so the caller can re-prompt and restart
    // the ceremony with a fresh PIN. `forcePinChange` is informational on
    // `cachedInfo` — mirroring python-fido2 and yubikit-android.
    //
    // Returns: (nil, nil) = no auth needed, (token, nil) = use token, (nil, true) = internal UV.
    func acquireAuthToken(
        info: CTAP2.GetInfo.Response,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String,
        userVerification: WebAuthn.UserVerificationPreference,
        isMakeCredential: Bool,
        allowUV: Bool = true,
        authorization: WebAuthn.Authorization
    ) async throws(WebAuthn.ClientError) -> (token: CTAP2.Token?, uv: Bool?) {

        let uvRequired = try isUserVerificationRequired(
            info: info,
            userVerification: userVerification,
            permissions: permissions,
            isMakeCredential: isMakeCredential
        )
        guard uvRequired else {
            return (token: nil, uv: nil)
        }

        let hasUV = info.options.userVerification == true
        let hasPin = info.options.clientPin == true
        // Internal UV only valid for basic operations (mc/ga), not management.
        let allowInternalUV = permissions.subtracting([.makeCredential, .getAssertion]).isEmpty
        let canTryUV = authorization.uv != .skipped && hasUV && allowUV
        let initialUVRetries = canTryUV ? ((try? await backend.getUVRetries()) ?? 0) : 0

        // External UV path: authenticator supports pinUVAuthToken.
        if initialUVRetries > 0, info.options.pinUVAuthToken == true {
            do throws(CTAP2.SessionError) {
                let token = try await backend.getPinUVToken(
                    using: .uv,
                    permissions: permissions,
                    rpId: rpId
                )
                return (token: token, uv: nil)
            } catch {
                switch error {
                case .ctapError(.uvInvalid, _), .ctapError(.uvBlocked, _):
                    // .required → strict UV-only, never fall through.
                    // Otherwise: fall through to PIN if available.
                    if authorization.uv == .required || !hasPin {
                        throw .uvBlocked(source: .here())
                    }
                // Fall through to PIN path below.
                default:
                    throw WebAuthn.ClientError(error)
                }
            }
        } else if initialUVRetries > 0, allowInternalUV {
            // Internal UV (authenticator handles UV during MC/GA itself).
            return (token: nil, uv: true)
        } else if authorization.uv == .required {
            // UV requested as strict-only but unavailable → uvBlocked.
            throw .uvBlocked(source: .here())
        }

        // PIN path: requires clientPin to be configured.
        guard hasPin else {
            throw .pinNotSet(source: .here())
        }

        let pin: String
        switch await authorization.providePIN() {
        case .pin(let value):
            pin = value
        case .cancel:
            throw .cancelled(source: .here())
        }

        do throws(CTAP2.SessionError) {
            let token = try await backend.getPinUVToken(
                using: .pin(pin),
                permissions: permissions,
                rpId: rpId
            )
            return (token: token, uv: nil)
        } catch {
            guard case .ctapError(.pinInvalid, _) = error else {
                throw WebAuthn.ClientError(error)
            }
            let retries: Int
            do {
                retries = try await backend.getPinRetries().retries
            } catch {
                throw WebAuthn.ClientError(error)
            }
            guard retries > 0 else {
                throw .pinBlocked(source: .here())
            }
            throw .pinRejected(retriesRemaining: retries, source: .here())
        }
    }
}

// MARK: - Private

extension WebAuthn.Client {

    // Determines if UV is required based on preference, authenticator flags, and operation type.
    // UV required if: explicit .required, .preferred with support, PIN set (even when discouraged),
    // alwaysUV enabled, registration without makeCredUVNotRequired, or management permissions.
    private func isUserVerificationRequired(
        info: CTAP2.GetInfo.Response,
        userVerification: WebAuthn.UserVerificationPreference,
        permissions: CTAP2.ClientPin.Permission,
        isMakeCredential: Bool
    ) throws(WebAuthn.ClientError) -> Bool {
        let options = info.options

        // Supported = capability exists, Configured = capability is enabled/enrolled.
        let uvSupported =
            options.userVerification != nil
            || options.clientPin != nil
            || options.bioEnroll != nil

        let uvConfigured =
            options.userVerification == true
            || options.clientPin == true
            || options.bioEnroll == true

        if userVerification == .required
            || (userVerification == .preferred && uvSupported)
            || (userVerification == .discouraged && options.clientPin == true)
            || options.alwaysUV == true
        {
            guard uvConfigured else {
                // PIN capability present but not configured: surface as
                // `.pinNotSet` so callers can route into a PIN-setup flow
                // instead of treating it as an unrecoverable failure.
                if options.clientPin != nil {
                    throw .pinNotSet(source: .here())
                }
                throw .notSupported("User verification not configured/supported", source: .here())
            }
            return true
        }

        if isMakeCredential && uvConfigured && options.makeCredUVNotRequired != true {
            return true
        }

        // Management operations always require UV.
        let additionalPerms = permissions.subtracting([.makeCredential, .getAssertion])
        if uvConfigured && !additionalPerms.isEmpty {
            return true
        }

        return false
    }
}
