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

public enum Platform: Sendable, Equatable {
    case all
    case macOS
    case iOS

    var runsHere: Bool {
        #if os(macOS)
        return self == .all || self == .macOS
        #else
        return self == .all || self == .iOS
        #endif
    }
}

public struct SourceLocation: Sendable, CustomStringConvertible {
    public let fileID: String
    public let line: Int
    init(fileID: String = #fileID, line: Int = #line) {
        self.fileID = fileID
        self.line = line
    }
    public var description: String { "\(fileID):\(line)" }
}

public struct Scenario: Sendable, Identifiable, Hashable, CustomStringConvertible {

    public enum Suite: String, CaseIterable, Sendable {
        case management, piv, oath, otp, connection, ctap2, ctaphid, webauthn, scp

        public var displayName: String {
            switch self {
            case .management: return "Management"
            case .piv: return "PIV"
            case .oath: return "OATH"
            case .otp: return "OTP"
            case .connection: return "Connection"
            case .ctap2: return "CTAP2"
            case .ctaphid: return "CTAPHID"
            case .webauthn: return "WebAuthn"
            case .scp: return "SCP"
            }
        }

        init(idPrefix id: String) {
            let head = id.prefix { $0 != "." }.lowercased()
            guard let suite = Suite(rawValue: head) else {
                preconditionFailure("scenario id '\(id)' has no matching Suite")
            }
            self = suite
        }
    }

    public let id: String
    public let suite: Suite
    public let name: String
    public let requirements: Requirements
    public let platform: Platform
    let run: @Sendable (Scenario.Context) async throws -> Void

    public var description: String { id }

    // Identity is the id; the body closure is not Equatable.
    public static func == (lhs: Scenario, rhs: Scenario) -> Bool { lhs.id == rhs.id }
    public func hash(into hasher: inout Hasher) { hasher.combine(id) }

    init(
        _ id: String,
        _ name: String,
        requirements: Requirements = .init(),
        platform: Platform = .all,
        run: @escaping @Sendable (Scenario.Context) async throws -> Void
    ) {
        self.id = id
        self.suite = Suite(idPrefix: id)
        self.name = name
        self.requirements = requirements
        self.platform = platform
        self.run = run
    }
}
