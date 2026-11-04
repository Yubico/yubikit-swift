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

extension DeviceInfo {
    /// Identifies a firmware release, including prerelease metadata.
    public struct VersionQualifier: Sendable, Equatable {

        /// The firmware release stage.
        public enum ReleaseType: UInt8, Sendable {
            /// An alpha release.
            case alpha = 0
            /// A beta release.
            case beta = 1
            /// A final release.
            case final = 2
        }

        /// The firmware version associated with this release.
        public let version: Version
        /// Whether this is an alpha, beta, or final release.
        public let releaseType: ReleaseType
        /// The build iteration within the release stage.
        public let iteration: UInt32
    }
}
