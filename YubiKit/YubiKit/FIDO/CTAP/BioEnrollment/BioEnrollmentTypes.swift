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

// MARK: - Public Types

extension CTAP2.BioEnrollment {

    /// Information about the fingerprint sensor hardware.
    public struct FingerprintSensorInfo: Sendable {
        /// The type of fingerprint sensor.
        public let fingerprintKind: FingerprintKind

        /// Maximum number of good fingerprint samples required for enrollment.
        public let maxCaptureSamplesRequired: UInt

        /// Maximum length of a template friendly name in bytes, if supported.
        public let maxTemplateFriendlyName: UInt?

        internal init(
            fingerprintKind: FingerprintKind,
            maxCaptureSamplesRequired: UInt,
            maxTemplateFriendlyName: UInt?
        ) {
            self.fingerprintKind = fingerprintKind
            self.maxCaptureSamplesRequired = maxCaptureSamplesRequired
            self.maxTemplateFriendlyName = maxTemplateFriendlyName
        }
    }

    /// The type of fingerprint sensor.
    public enum FingerprintKind: Sendable, Equatable {
        /// Touch-type sensor (place finger and hold).
        case touch
        /// Swipe-type sensor (swipe finger across).
        case swipe
        /// Unrecognized sensor type.
        case other(UInt8)

        internal static func from(_ rawValue: UInt8) -> FingerprintKind {
            switch rawValue {
            case 1: return .touch
            case 2: return .swipe
            default: return .other(rawValue)
            }
        }
    }

    /// Feedback status for a fingerprint capture sample.
    public enum SampleStatus: Sendable, Equatable {
        /// Good fingerprint capture.
        case good
        /// Fingerprint was too high.
        case tooHigh
        /// Fingerprint was too low.
        case tooLow
        /// Fingerprint was too left.
        case tooLeft
        /// Fingerprint was too right.
        case tooRight
        /// Finger moved too fast.
        case tooFast
        /// Finger moved too slow.
        case tooSlow
        /// Fingerprint image was poor quality.
        case poorQuality
        /// Fingerprint was too skewed.
        case tooSkewed
        /// Fingerprint was too short (swipe sensor).
        case tooShort
        /// Merge failure of the capture.
        case mergeFailure
        /// Fingerprint already exists in database.
        case exists
        /// No user activity detected on the sensor.
        case noUserActivity
        /// No user presence transition detected.
        case noUserPresenceTransition
        /// Unrecognized status code.
        case other(UInt8)

        internal static func from(_ rawValue: UInt8) -> SampleStatus {
            switch rawValue {
            case 0x00: return .good
            case 0x01: return .tooHigh
            case 0x02: return .tooLow
            case 0x03: return .tooLeft
            case 0x04: return .tooRight
            case 0x05: return .tooFast
            case 0x06: return .tooSlow
            case 0x07: return .poorQuality
            case 0x08: return .tooSkewed
            case 0x09: return .tooShort
            case 0x0A: return .mergeFailure
            case 0x0B: return .exists
            case 0x0D: return .noUserActivity
            case 0x0E: return .noUserPresenceTransition
            default: return .other(rawValue)
            }
        }
    }

    /// Information about an enrolled fingerprint template.
    public struct TemplateInfo: Sendable {
        /// The template identifier.
        public let templateId: Data

        /// The user-assigned friendly name, if set.
        public let friendlyName: String?

        internal init(templateId: Data, friendlyName: String?) {
            self.templateId = templateId
            self.friendlyName = friendlyName
        }
    }
}

// MARK: - Internal Types

extension CTAP2.BioEnrollment {
    struct EnrollBeginResult: Sendable {
        let templateId: Data
        let sampleStatus: SampleStatus
        let remainingSamples: UInt
    }

    struct CaptureResult: Sendable {
        let sampleStatus: SampleStatus
        let remainingSamples: UInt
    }

    struct EnumerateEnrollmentsResponse: Sendable {
        let templateInfos: [TemplateInfo]
    }
}
