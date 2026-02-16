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

// MARK: - Response Keys

extension CTAP2.BioEnrollment {
    fileprivate enum ResponseKey: Int {
        case fingerprintKind = 0x02
        case maxCaptureSamplesRequired = 0x03
        case templateId = 0x04
        case lastEnrollSampleStatus = 0x05
        case remainingSamples = 0x06
        case templateInfos = 0x07
        case maxTemplateFriendlyName = 0x08
    }

    fileprivate enum TemplateInfoKey: Int {
        case templateId = 0x01
        case templateFriendlyName = 0x02
    }
}

// MARK: - FingerprintSensorInfo + CBOR

extension CTAP2.BioEnrollment.FingerprintSensorInfo: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else { return nil }
        typealias Key = CTAP2.BioEnrollment.ResponseKey
        guard
            let kindRaw = map[.int(Key.fingerprintKind.rawValue)]?.uint64Value,
            let maxSamples = map[.int(Key.maxCaptureSamplesRequired.rawValue)]?.uint64Value
        else { return nil }
        self.init(
            fingerprintKind: .from(UInt8(kindRaw)),
            maxCaptureSamplesRequired: UInt(maxSamples),
            maxTemplateFriendlyName: map[.int(Key.maxTemplateFriendlyName.rawValue)]?.uint64Value
                .map { UInt($0) }
        )
    }
}

// MARK: - EnrollBeginResult + CBOR

extension CTAP2.BioEnrollment.EnrollBeginResult: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else { return nil }
        typealias Key = CTAP2.BioEnrollment.ResponseKey
        guard
            let templateId = map[.int(Key.templateId.rawValue)]?.dataValue,
            let statusRaw = map[.int(Key.lastEnrollSampleStatus.rawValue)]?.uint64Value,
            let remaining = map[.int(Key.remainingSamples.rawValue)]?.uint64Value
        else { return nil }
        let sampleStatus = CTAP2.BioEnrollment.SampleStatus.from(UInt8(statusRaw))
        self.init(templateId: templateId, sampleStatus: sampleStatus, remainingSamples: UInt(remaining))
    }
}

// MARK: - CaptureResult + CBOR

extension CTAP2.BioEnrollment.CaptureResult: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else { return nil }
        typealias Key = CTAP2.BioEnrollment.ResponseKey
        guard
            let statusRaw = map[.int(Key.lastEnrollSampleStatus.rawValue)]?.uint64Value,
            let remaining = map[.int(Key.remainingSamples.rawValue)]?.uint64Value
        else { return nil }
        let sampleStatus = CTAP2.BioEnrollment.SampleStatus.from(UInt8(statusRaw))
        self.init(sampleStatus: sampleStatus, remainingSamples: UInt(remaining))
    }
}

// MARK: - TemplateInfo + CBOR

extension CTAP2.BioEnrollment.TemplateInfo: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else { return nil }
        typealias Key = CTAP2.BioEnrollment.TemplateInfoKey
        guard let templateId = map[.int(Key.templateId.rawValue)]?.dataValue else { return nil }
        self.init(
            templateId: templateId,
            friendlyName: map[.int(Key.templateFriendlyName.rawValue)]?.stringValue
        )
    }
}

// MARK: - EnumerateEnrollmentsResponse + CBOR

extension CTAP2.BioEnrollment.EnumerateEnrollmentsResponse: CBOR.Decodable {
    init?(cbor: CBOR.Value) {
        guard let map = cbor.mapValue else { return nil }
        typealias Key = CTAP2.BioEnrollment.ResponseKey
        guard let infosArray = map[.int(Key.templateInfos.rawValue)]?.arrayValue else { return nil }
        self.init(templateInfos: infosArray.compactMap { $0.cborDecoded() })
    }
}
