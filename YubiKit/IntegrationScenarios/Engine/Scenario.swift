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

enum Platform: Sendable, Equatable {
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

@_spi(YubiInternal) public struct SourceLocation: Sendable, CustomStringConvertible {
    let fileID: String
    let line: Int
    init(fileID: String = #fileID, line: Int = #line) {
        self.fileID = fileID
        self.line = line
    }
    public var description: String { "\(fileID):\(line)" }
}

@_spi(YubiInternal) public struct Scenario: Sendable, Identifiable, Hashable, CustomStringConvertible {

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
    let platform: Platform
    /// The interface this variant runs CTAP2 over; `nil` uses the backend's default.
    let ctap2Transport: CTAP2Transport?
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
        ctap2Transport: CTAP2Transport? = nil,
        run: @escaping @Sendable (Scenario.Context) async throws -> Void
    ) {
        self.id = id
        self.suite = Suite(idPrefix: id)
        self.name = name
        self.requirements = requirements
        self.platform = platform
        self.ctap2Transport = ctap2Transport
        self.run = run
    }

    /// This scenario pinned to one CTAP2 interface: FIDO HID (unavailable on iOS and NFC) or the
    /// smart-card (CCID) interface.
    fileprivate func over(_ transport: CTAP2Transport) -> Scenario {
        let isHID = transport == .fido
        var requirements = requirements
        requirements.requiresFIDOTransport = isHID
        requirements.requiresCTAP2OverCCID = !isHID
        return Scenario(
            "\(id).\(isHID ? "hid" : "ccid")",
            "\(name) (\(isHID ? "HID" : "CCID"))",
            requirements: requirements,
            platform: platform,
            ctap2Transport: transport,
            run: run
        )
    }
}

extension [Scenario] {
    /// Every scenario over FIDO HID, then over CCID, each pass from its own clean state. A scenario
    /// that needs FIDO HID (such as keepalive cancel) runs only over HID.
    func overEveryCTAP2Transport() -> [Scenario] {
        map { $0.over(.fido) } + filter { !$0.requirements.requiresFIDOTransport }.map { $0.over(.ccid) }
    }
}
