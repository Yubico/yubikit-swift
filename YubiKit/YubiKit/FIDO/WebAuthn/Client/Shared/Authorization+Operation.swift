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

extension WebAuthn.Authorization {
    enum Operation {
        case makeCredential(residentKey: Bool)
        case getAssertion(hasAllowList: Bool)
    }
}

extension WebAuthn.Authorization.Operation {

    func requiresUserVerification(
        info: CTAP2.GetInfo.Response,
        preference: WebAuthn.UserVerificationPreference,
        permissions: CTAP2.ClientPin.Permission
    ) throws(WebAuthn.ClientError) -> Bool {
        let options = info.options

        let uvConfigured =
            options.userVerification == true
            || options.clientPin == true
            || options.bioEnroll == true

        let uvSupported =
            options.userVerification != nil
            || options.clientPin != nil
            || options.bioEnroll != nil

        let forcedUV = options.alwaysUV == true
        let hasExtraPermissions = !permissions.subtracting([.makeCredential, .getAssertion]).isEmpty

        switch (uvConfigured, uvSupported, preference, forcedUV, self) {
        case (false, _, .required, _, _),
            (false, true, .preferred, _, _),
            (false, _, _, true, _):
            // Requested or enforced UV needs configuration first.
            if options.clientPin != nil {
                throw .pinNotSet(source: .here())
            }
            throw .notSupported("User verification not configured/supported", source: .here())

        case (false, _, _, _, _):
            // No configured UV and no requirement to use it.
            return false

        case (true, _, .required, _, _),
            (true, _, .preferred, _, _),
            (true, _, _, true, _):
            // Use configured UV when requested or enforced.
            return true

        case _ where hasExtraPermissions:
            // Extra permissions, such as large-blob writes, require UV.
            return true

        case (_, _, _, _, .makeCredential(let residentKey)):
            // Only non-resident registration can use the authenticator's UV exemption.
            return residentKey || options.makeCredUVNotRequired != true

        case (_, _, _, _, .getAssertion(let hasAllowList)):
            // Account selection needs UV to expose account names.
            return !hasAllowList
        }
    }
}
