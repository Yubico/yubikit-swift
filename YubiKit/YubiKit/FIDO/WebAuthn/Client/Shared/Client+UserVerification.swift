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
        // TODO: Handle .pinAuthBlocked by reconnecting NFC (see python-fido2)
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

    // MARK: - UV Decision Flow

    // Yields `.requestingUV` and waits for user to choose between UV and PIN.
    func awaitUVDecision<R: Sendable>(
        from continuation: WebAuthn.StatusStream<R>.Continuation
    ) async -> Bool {
        await withCheckedContinuation { checkedContinuation in
            continuation.yield(
                .requestingUV { proceed in
                    checkedContinuation.resume(returning: proceed)
                }
            )
        }
    }

    // MARK: - Token Acquisition

    // Acquires PIN/UV auth token if required.
    // Returns: (nil, nil) = no auth needed, (token, nil) = use token, (nil, true) = internal UV.
    func acquireAuthToken(
        info: CTAP2.GetInfo.Response,
        permissions: CTAP2.ClientPin.Permission,
        rpId: String,
        userVerification: WebAuthn.UserVerificationPreference,
        isMakeCredential: Bool,
        allowUV: Bool = true,
        requestUVApproval: (@Sendable () async -> Bool)? = nil
    ) async throws(WebAuthn.Error) -> (token: CTAP2.Token?, uv: Bool?) {

        let uvRequired = try isUserVerificationRequired(
            info: info,
            userVerification: userVerification,
            permissions: permissions,
            isMakeCredential: isMakeCredential
        )
        guard uvRequired else {
            return (token: nil, uv: nil)
        }

        let hasPin = info.options.clientPin == true
        let hasUV = info.options.userVerification == true
        // Internal UV only valid for basic operations (mc/ga), not management.
        let allowInternalUV = permissions.subtracting([.makeCredential, .getAssertion]).isEmpty

        let uvRetries = hasUV && allowUV ? (try? await session.getUVRetries()) ?? 0 : 0

        // Try UV-based authentication if available.
        if uvRetries > 0, info.options.pinUVAuthToken == true {
            let proceedWithUV = await requestUVApproval?() ?? true

            if proceedWithUV {
                do throws(CTAP2.SessionError) {
                    let token = try await session.getPinUVToken(
                        using: .uv,
                        permissions: permissions,
                        rpId: rpId
                    )
                    return (token: token, uv: nil)
                } catch {
                    switch error {
                    case .ctapError(.uvBlocked, _),
                        .ctapError(.operationDenied, _),
                        .ctapError(.unauthorizedPermission, _):
                        guard hasPin else {
                            let retries = try? await session.getUVRetries()
                            throw .userVerificationFailed(
                                retriesRemaining: retries,
                                source: .here()
                            )
                        }
                    // Fall through to PIN.
                    default:
                        throw WebAuthn.Error(error)
                    }
                }
            }
        } else if uvRetries > 0, allowInternalUV {
            // Use internal UV (authenticator handles UV during command).
            return (token: nil, uv: true)
        }

        // Fall back to PIN.
        guard let pinProvider else {
            throw .pinRequired(source: .here())
        }
        guard let pin = await pinProvider() else {
            throw .cancelled(source: .here())
        }

        do throws(CTAP2.SessionError) {
            let token = try await session.getPinUVToken(
                using: .pin(pin),
                permissions: permissions,
                rpId: rpId
            )
            return (token: token, uv: nil)
        } catch {
            if case .ctapError(.pinInvalid, _) = error {
                let retries = (try? await session.getPinRetries())?.retries ?? 0
                throw .invalidPIN(retriesRemaining: retries, source: .here())
            }
            throw WebAuthn.Error(error)
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
    ) throws(WebAuthn.Error) -> Bool {
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
