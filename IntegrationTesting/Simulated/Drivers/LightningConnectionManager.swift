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

#if os(iOS)

import Foundation

// Simulators have no Lightning accessory transport.
actor LightningConnectionManager {
    static let shared = LightningConnectionManager()

    func connect() async throws(SmartCardConnectionError) -> ConnectionLifetime {
        if Task.isCancelled { throw .cancelled }
        throw .unsupported
    }

    func transmit(
        request: Data,
        id: UUID
    ) async throws(SmartCardConnectionError) -> Data {
        throw .connectionLost
    }

    func close(id: UUID, error: Error?) {}
}

#endif
