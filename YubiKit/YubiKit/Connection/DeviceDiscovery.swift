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

// Shared polling for connection initializers that wait for a device.
func waitForDevice<Device: Sendable, Failure: Error>(
    cancellationError: Failure,
    discover: @Sendable () async throws(Failure) -> [Device]
) async throws(Failure) -> Device {
    while true {
        guard !Task.isCancelled else { throw cancellationError }
        let devices = try await discover()
        guard !Task.isCancelled else { throw cancellationError }
        if let device = devices.first { return device }
        do {
            try await Task.sleep(for: .seconds(1))
        } catch {
            throw cancellationError
        }
    }
}
