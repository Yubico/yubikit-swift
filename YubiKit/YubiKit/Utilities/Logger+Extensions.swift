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

import OSLog

extension Logger {
    private static var subsystem = "com.yubico.YubiKit"

    static let connection = Logger(subsystem: subsystem, category: "Connection")
    
    static let nfc = Logger(subsystem: subsystem, category: "NFC")
    static let lightning = Logger(subsystem: subsystem, category: "Lightning")
    static let smartCard = Logger(subsystem: subsystem, category: "SmartCard")

    static let oath = Logger(subsystem: subsystem, category: "OATH")
    static let management = Logger(subsystem: subsystem, category: "Management")
}
