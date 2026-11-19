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

/// Namespace for USB SmartCard related types.
public enum USBSmartCard {
    /// Represents a YubiKey device available as a smart card slot.
    public struct YubiKeyDevice: Sendable, Hashable, CustomStringConvertible {
        /// The name of the smart card slot.
        public let name: String

        /// String representation of the device, same as name.
        public var description: String { name }

        init(name: String) {
            self.name = name
        }
    }

    // A YubiKey's own USB CCID interface reports 0xFx in the second ATR byte; anything else is
    // a card presented to an external (NFC) reader.
    static func isNFC(atr: Data?) -> Bool {
        guard let atr, atr.count > 1 else { return true }
        return atr[atr.startIndex + 1] & 0xf0 != 0xf0
    }
}
