//
//  OATHSession.swift
//  YubiKit
//
//  Created by Jens Utbult on 2021-11-23.
//

import Foundation

public struct Code: Identifiable {
    public let id = UUID()
    public let code: String
}

public final class OATHSession: Session, InternalSession {
    
    internal weak var connection: Connection?
    private var sessionEnded = false
    var endingResult: Result<String, Error>?

    private init(connection: Connection) async throws {
        self.connection = connection
        let data = Data([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01])
        let selectOathApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x04, p2: 0x00, data: data, type: .short)
        let result = try await connection.send(apdu: selectOathApdu)
        print("select application: \(data.hexDescription)")
        print("Select OATH app result:")
        print(result)
//        try await connection.smartCardInterface.selectApplication(application: .OATH)
        var internalConnection = self.internalConnection
        internalConnection.session = self
    }
    
    public static func session(withConnection connection: Connection) async throws -> OATHSession {
        // Close active session if there is one
        let internalConnection = connection as! InternalConnection
        await internalConnection.session?.end(withConnectionStatus: .leaveOpen)
        // Create a new OATHSession
        let session = try await OATHSession(connection: connection)
        return session
    }
    
    public func end(withConnectionStatus status: ConnectionStatus = .leaveOpen) async {
        switch status {
        case .close(let result):
            endingResult = result
            await connection?.close(result: result)
        default: break
        }
        sessionEnded = true
        var internalConnection = self.internalConnection
        internalConnection.session = nil
        connection = nil
        if case .leaveOpen = status {
            print("End OATHSesssion and close connection")
        } else {
            print("End OATHSesssion")
        }
    }
    
    public func sessionDidEnd() async throws -> Error? {
        print("await OATH sessionDidEnd")
//        _ = try await connection?.send(apdu: APDU())
        print("OATH session did end\(endingResult != nil ? " with result: \(endingResult!)" : "")")
        return nil
    }

    public func calculateCode() async throws -> Code {
        print("Start OATH calculateCode()")
//        _ = try await connection?.send(apdu: APDU())
        print("Finished calculateCode()")
        return Code(code: "\(Int.random(in: 1000...9999))")
    }
    
    public func calculateCodes(timestamp: Date = Date()) async throws -> [Code] {
        print("Start OATH calculateCodes")
        // Not fully implemented yet. Returning fake codes.
        return (1...6).map { _ in Code(code: "\(Int.random(in: 1000...9999))") }
        
        let time = timestamp.timeIntervalSince1970
        let challenge = UInt64(time / 30)
        let bigChallenge = CFSwapInt64HostToBig(challenge)
        var data = Data()
        data.append(0x74)
        data.append(bigChallenge.data)
        let calculateAllApdu = APDU(cla: 0x00, ins: 0xa4, p1: 0x00, p2: 0x01, data: data, type: .short)
        guard let connection = connection else { throw "No connection to YubiKey!" }
        let result = try await connection.send(apdu: calculateAllApdu)
        print(result.hexDescription)
        print(result.responseStatusCode)
        guard result.responseStatusCode == 0x9000 else {
            print("Status code error: \(result.responseStatusCode)")
            throw "APDU error: \(result.responseStatusCode)"
        }
        print(result.hexDescription)
        print(result.responseStatusCode)
        print(result.responseData.hexDescription)
        if result.responseStatusCode == 0x9000 {
            print("status code ok")
        }
        print("Finished OATH calculateCodes\n")
        return (1...6).map { _ in Code(code: "\(Int.random(in: 1000...9999))") }
        
    }
    
    public func calculateFailingCode() async throws -> String {
//        _ = try await connection?.send(apdu: APDU())
        throw "Something went wrong!"
    }

    deinit {
        print("deinit OATHSession")
    }
}

extension Data {
    var responseStatusCode: UInt16 {
        let data = self.subdata(in: self.count - 2..<self.count)
        return CFSwapInt16BigToHost(data.uint16)
    }
    
    var responseData: Data {
        return self.subdata(in: 0..<self.count - 2)
    }
    
    
}
