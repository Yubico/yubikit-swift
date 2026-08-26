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

extension Scenario {

    public struct Failure: Sendable, Identifiable {
        public let id = UUID()
        public let message: String
        public let location: SourceLocation

        init(message: String, location: SourceLocation) {
            self.message = message
            self.location = location
        }
    }

    public struct Result: Sendable, Identifiable {
        public enum Status: Sendable, Equatable {
            case running
            case passed
            case failed
            case errored
            case skipped(reason: String)
            /// No allowed backend was reachable.
            case backendUnavailable(reason: String)
        }

        public let scenario: Scenario
        public let status: Status
        public let failures: [Failure]
        public let thrownError: String?
        public let duration: Duration
        public let logs: [String]

        public var id: String { scenario.id }

        public init(
            scenario: Scenario,
            status: Status,
            failures: [Failure] = [],
            thrownError: String? = nil,
            duration: Duration = .zero,
            logs: [String] = []
        ) {
            self.scenario = scenario
            self.status = status
            self.failures = failures
            self.thrownError = thrownError
            self.duration = duration
            self.logs = logs
        }
    }

    /// Live progress signals for the UI.
    public enum Event: Sendable {
        case started(Scenario)
        case touchPrompt(Scenario, String)
        case finished(Result)
    }
}
