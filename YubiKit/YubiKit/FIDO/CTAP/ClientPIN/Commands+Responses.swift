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

// MARK: - GetRetries Response

extension CTAP2.ClientPin.GetRetries {
    /// Response from getPinRetries.
    struct Response: Sendable {
        /// Number of PIN retries remaining before lockout.
        let retries: Int

        /// Whether a power cycle is required before PIN operations can continue.
        let powerCycleState: Bool

        init(retries: Int, powerCycleState: Bool = false) {
            self.retries = retries
            self.powerCycleState = powerCycleState
        }
    }
}

// MARK: - GetKeyAgreement Response

extension CTAP2.ClientPin.GetKeyAgreement {
    /// Response from getKeyAgreement.
    struct Response: Sendable {
        /// Authenticator's public key for ECDH key agreement.
        let keyAgreement: COSE.Key

        init(keyAgreement: COSE.Key) {
            self.keyAgreement = keyAgreement
        }
    }
}

// MARK: - GetToken Response

extension CTAP2.ClientPin.GetToken {
    /// Response from getPinToken.
    struct Response: Sendable {
        /// Encrypted PIN/UV auth token.
        let pinUVAuthToken: Data

        init(pinUVAuthToken: Data) {
            self.pinUVAuthToken = pinUVAuthToken
        }
    }
}

// MARK: - GetUVRetries Response

extension CTAP2.ClientPin.GetUVRetries {
    /// Response from getUVRetries.
    struct Response: Sendable {
        /// Number of UV retries remaining before UV is disabled.
        let retries: Int

        init(retries: Int) {
            self.retries = retries
        }
    }
}
