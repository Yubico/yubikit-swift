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

import CryptoTokenKit
#if os(iOS)
import CoreNFC
import ExternalAccessory
#endif

package enum ConnectionEnvironment {
    package static var configurationError: String? { nil }
    package static var isVirtual: Bool { false }
    package static var hasSmartCardReader: Bool { TKSmartCardSlotManager.default != nil }
    package static var supportsSecureChannel: Bool { true }
    package static var hasNFCReader: Bool {
        #if os(iOS)
        NFCReaderSession.readingAvailable
        #else
        false
        #endif
    }

    #if os(iOS)
    @MainActor package static var hasLightningKey: Bool {
        EAAccessoryManager.shared().connectedAccessories.contains {
            $0.protocolStrings.contains("com.yubico.ylp") && $0.manufacturer == "Yubico"
        }
    }
    #endif

    package static func reinsertVirtualKey() async throws {}
}
