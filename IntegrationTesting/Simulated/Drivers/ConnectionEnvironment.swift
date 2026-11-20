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

import YubiKitTwinSupport

package enum ConnectionEnvironment {
    package static var configurationError: String? { TwinKitBackend.environmentProfileConfigurationError }
    package static var isVirtual: Bool { true }
    package static var hasSmartCardReader: Bool { true }
    package static var supportsSecureChannel: Bool {
        (try? TwinKitBackend.shared.descriptor().supportsSecureChannel) == true
    }
    package static var hasNFCReader: Bool { TwinKitConfiguration.hasNFCReader }

    #if os(iOS)
    @MainActor package static var hasLightningKey: Bool { false }
    #endif

    package static func reinsertVirtualKey() async throws {
        try Task.checkCancellation()
        let transport: TwinKitSmartCardTransport =
            switch try TwinKitConfiguration.selectedTransport() {
            case .usb: .usb
            case .nfc: .nfc
            }
        try await TwinKitBackend.shared.reinsert(over: transport)
    }
}
