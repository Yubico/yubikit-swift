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
import OSLog

/*
 Smart Card APDU Communication Infrastructure

 This file contains the layered APDU communication system for YubiKey smart card operations.

 Naming Convention:
 - `process(apdu:)` = Session-level APDU processing (handles SCP decisions)
   - Used by session implementations
   - Decides whether to use secure channel or plain transmission
   - Examples: ManagementSession.process(), PIVSession.process()

 - `send*()` = Low-level APDU transmission utilities
   - Used internally for actual wire communication
   - Examples: sendWithSecureChannel(), send(), sendWithErrorConversion()

 Flow:
   Session Code → session.process(apdu:) → [SCP decision] → internal send*() → Hardware
 */

// MARK: - Public API

public enum Application: Sendable {
    case oath
    case management
    case piv
    case securityDomain
}

// MARK: - Session APDU Processing Methods

extension SmartCardSession {
    @discardableResult
    func process(apdu: APDU) async throws(Self.Error) -> Data {

        let isOATH = Self.application == .oath
        let insSendRemaining: UInt8? = isOATH ? 0xa5 : nil

        if let scpState {
            return try await Self.send(
                apdu: apdu,
                using: connection,
                scpState: scpState,
                encrypt: true,
                insSendRemaining: insSendRemaining
            )
        } else {
            return try await send(apdu: apdu, insSendRemaining: insSendRemaining)
        }
    }
}

// MARK: - Internal API (used by other YubiKit modules)

extension SmartCardSession {
    @discardableResult
    static func selectApplication(using connection: SmartCardConnection) async throws(Self.Error) -> Data {
        if application == .oath {
            return try await send(
                apdu: application.selectionCommand,
                using: connection,
                insSendRemaining: 0xa5
            )
        } else {
            return try await send(
                apdu: application.selectionCommand,
                using: connection,
                insSendRemaining: nil
            )
        }
    }
}

// Senf with SCP
extension SmartCardSession {
    static func send(
        apdu: APDU,
        using connection: SmartCardConnection,
        scpState: SCPState,
        encrypt: Bool,
        insSendRemaining: UInt8?
    ) async throws(Self.Error) -> Data {
        let data: Data
        if encrypt {
            do {
                data = try await scpState.encrypt(apdu.command ?? Data())
            } catch {
                throw .encryptionFailed("Failed to encrypt APDU command", error: error)
            }
        } else {
            data = apdu.command ?? Data()
        }
        let cla = apdu.cla | 0x04

        let mac: Data
        do {
            mac = try await scpState.mac(
                data: APDU(
                    cla: cla,
                    ins: apdu.ins,
                    p1: apdu.p1,
                    p2: apdu.p2,
                    command: data + Data(count: 8),
                    type: .extended
                ).data.dropLast(8)
            )
        } catch {
            throw .encryptionFailed("Failed to calculate MAC", error: error)
        }

        let apdu = APDU(cla: cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, command: data + mac, type: .extended)
        var result = try await send(apdu: apdu, using: connection, insSendRemaining: insSendRemaining)

        if !result.isEmpty {
            do {
                result = try await scpState.unmac(data: result, sw: 0x9000)
            } catch {
                throw .scpError(error)
            }
        }
        if !result.isEmpty {
            do {
                result = try await scpState.decrypt(result)
            } catch {
                throw .encryptionFailed("Failed to decrypt result", error: error)
            }
        }

        return result
    }
}

// Send without SCP
extension SmartCardSession {
    @discardableResult
    func send(apdu: APDU, insSendRemaining: UInt8?) async throws(Self.Error) -> Data {
        try await Self.send(apdu: apdu, using: connection, insSendRemaining: insSendRemaining)
    }
}

// MARK: - File-Private Implementation Details

extension Application {
    fileprivate var selectionCommand: APDU {
        let data: Data
        switch self {
        case .oath:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
        case .management:
            data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17])
        case .piv:
            data = Data([0xA0, 0x00, 0x00, 0x03, 0x08])
        case .securityDomain:
            data = Data([0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00])
        }

        return APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, command: data)
    }
}

extension SmartCardSession {
    @discardableResult
    func send(
        apdu: APDU,
        using connection: SmartCardConnection,
        insSendRemaining: UInt8?
    ) async throws(Self.Error) -> Data {
        try await Self.send(apdu: apdu, using: connection, insSendRemaining: insSendRemaining)
    }

    @discardableResult
    static func send(
        apdu: APDU,
        using connection: SmartCardConnection,
        insSendRemaining: UInt8?
    ) async throws(Self.Error) -> Data {
        try await sendAPDUWithContinuation(
            apdu: apdu,
            using: connection,
            readMoreData: false,
            insSendRemaining: insSendRemaining ?? 0xc0
        )
    }
}

// MARK: - Private Implementation Details

extension SmartCardSession {
    fileprivate static func sendAPDUWithContinuation(
        apdu: APDU,
        using connection: SmartCardConnection,
        data: Data = Data(),
        readMoreData: Bool,
        insSendRemaining: UInt8
    ) async throws(Self.Error) -> Data {
        Logger.connection.debug("SmartCardHelpers, \(#function): accumulated data: \(data)")

        let responseData: Data
        let response: Response

        do {
            if readMoreData {
                let apdu = APDU(cla: 0, ins: insSendRemaining, p1: 0, p2: 0, command: nil)
                responseData = try await connection.send(data: apdu.data)
            } else {
                responseData = try await connection.send(data: apdu.data)
            }
        } catch {
            throw .connectionError(error)
        }

        response = Response(rawData: responseData)

        guard response.responseStatus.status == .ok || response.responseStatus.sw1 == 0x61 else {
            Logger.connection.error(
                "SmartCardHelpers, \(#function): failed with statusCode: \(response.responseStatus.status)"
            )
            throw .failedResponse(response.responseStatus)
        }

        let newData = data + response.data
        if response.responseStatus.sw1 == 0x61 {
            return try await sendAPDUWithContinuation(
                apdu: apdu,
                using: connection,
                data: newData,
                readMoreData: true,
                insSendRemaining: insSendRemaining
            )
        } else {
            Logger.connection.debug(
                "SmartCardHelpers, \(#function): response: \(newData.hexEncodedString)"
            )
            return newData
        }
    }
}
