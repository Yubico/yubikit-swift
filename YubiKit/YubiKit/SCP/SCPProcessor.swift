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

fileprivate let insInitializeUpdate: UInt8 = 0x50

internal class SCPProcessor: Processor {
    
    private var state: SCPState
    
    internal init(connection: Connection, keyParams: SCPKeyParams) async throws {
        if let scp03Params = keyParams as? SCP03KeyParams {
            let hostChallenge = Data.random(length: 8)
            print("Send challenge: \(hostChallenge.hexEncodedString)")
            var result = try await connection.send(apdu: APDU(cla: 0x80, ins: insInitializeUpdate, p1: keyParams.keyRef.kvn, p2: 0x00, command: hostChallenge))
            
            guard let diversificationData = result.extract(10),
                  let keyInfo = result.extract(3),
                  let cardChallenge = result.extract(8),
                  let cardCryptogram = result.extract(8) else { fatalError("Malformed challenge response") }
            
            let context = hostChallenge + cardChallenge
            let sessionKeys = scp03Params.staticKeys.derive(context: context)
            
            let genCardCryptogram = try StaticKeys.deriveKey(key: sessionKeys.smac, t: 0x00, context: context, l: 0x40)
            
            guard genCardCryptogram.constantTimeCompare(cardCryptogram) == true else {
                fatalError("Wrong SCP03 key set") // TODO: throw an error here instead
            }
            
            let hostCryptogram = try StaticKeys.deriveKey(key: sessionKeys.smac, t: 0x01, context: context, l: 0x40)
            
            self.state = SCPState(sessionKeys: sessionKeys, macChain: Data(count: 16))

            let finalizeApdu = APDU(cla: 0x84, ins: 0x82, p1: 0x33, p2: 0, command: hostCryptogram)
            let finalizeResult = try await self.send(apdu: finalizeApdu, using: connection, encrypt: false)
            
            print("✅ done configuring SCP03")
            return
        }
        
        fatalError("Not implemented")
    }
    
    internal init(state: SCPState) {
        self.state = state
    }
    
    internal func send(apdu: APDU, using connection: any Connection) async throws -> Data {
        return try await self.send(apdu: apdu, using: connection, encrypt: true)
    }
    
    private func send(apdu: APDU, using connection: any Connection, encrypt: Bool) async throws -> Data {
        print("👾 process \(apdu), \(state)")
        let data: Data
        if encrypt {
            data = try state.encrypt(apdu.command ?? Data())
        } else {
            data = apdu.command ?? Data()
        }
        let cla = apdu.cla   | 0x04

        let mac = try state.mac(data: APDU(cla: cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, command: data + Data(count: 8)).data.dropLast(8))
        
        var result = try await connection.sendRecursive(apdu: APDU(cla: cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, command: data + mac))
        
        if !result.isEmpty {
           result = try state.unmac(data: result, sw: 0x9000)
        }
        if !result.isEmpty {
            result = try state.decrypt(result)
        }
        
        return result
    }
}
