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

/// A protocol defining a session with a specific application on the YubiKey.
///
/// Session is the base protocol for all YubiKey application sessions. Using a session is the preferred way
/// of communicating with the different applications on the YubiKey.
public protocol Session: Sendable {

    /// The type of features supported by this session.
    associatedtype Feature: SessionFeature

    /// Determine whether the Session supports the specific feature.
    func supports(_ feature: Feature) async -> Bool
}

/// A protocol defining a feature that can be supported by a session.
public protocol SessionFeature: Sendable {
    /// Determines if this feature is supported by the given firmware version.
    /// - Parameter version: The firmware version to check against.
    /// - Returns: true if the feature is supported, false otherwise.
    func isSupported(by version: Version) -> Bool
}
