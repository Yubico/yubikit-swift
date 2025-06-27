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

/// # PublicKey
/// Top-level public key enum supporting RSA, EC, and Curve25519 keys.

import Foundation

/// Generic public key (RSA, EC, Ed25519, or X25519).
public enum PublicKey: Sendable, Equatable {
    case ec(EC.PublicKey)
    case rsa(RSA.PublicKey)
    case ed25519(Curve25519.Ed25519.PublicKey)
    case x25519(Curve25519.X25519.PublicKey)
}
