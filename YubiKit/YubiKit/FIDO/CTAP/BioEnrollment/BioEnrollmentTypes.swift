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
    public enum FingerprintKind: UInt8, Sendable {
        /// Touch-type sensor (place finger and hold).
        case touch = 1
        /// Swipe-type sensor (swipe finger across).
        case swipe = 2
    }

    /// Feedback status for a fingerprint capture sample.
    public enum SampleStatus: UInt8, Sendable, Equatable {
        /// Good fingerprint capture.
        case good = 0x00
        /// Fingerprint was too high.
        case tooHigh = 0x01
        /// Fingerprint was too low.
        case tooLow = 0x02
        /// Fingerprint was too left.
        case tooLeft = 0x03
        /// Fingerprint was too right.
        case tooRight = 0x04
        /// Finger moved too fast.
        case tooFast = 0x05
        /// Finger moved too slow.
        case tooSlow = 0x06
        /// Fingerprint image was poor quality.
        case poorQuality = 0x07
        /// Fingerprint was too skewed.
        case tooSkewed = 0x08
        /// Fingerprint was too short (swipe sensor).
        case tooShort = 0x09
        /// Merge failure of the capture.
        case mergeFailure = 0x0A
        /// Fingerprint already exists in database.
        case exists = 0x0B
        // 0x0C is reserved (unused per CTAP 2.2 spec).
        /// No user activity detected on the sensor.
        case noUserActivity = 0x0D
        /// No user presence transition detected.
        case noUserPresenceTransition = 0x0E
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

    struct GetModalityResponse: Sendable {
        let modality: Modality
    }
}
