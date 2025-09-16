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
import YubiKit

struct Account: Identifiable {
    var id = UUID()
    let label: String
    let code: String?
    let issuer: String?
    let type: OATHSession.CredentialType
}

@MainActor
class Model: ObservableObject {

    @Published private(set) var accounts = [Account]()
    @Published private(set) var keyVersion: String?
    @Published private(set) var connectionType: String?
    @Published var error: Error?

    func update(using connection: SmartCardConnection) async {
        await calculateCodes(using: connection)
        await getKeyVersion(using: connection)
        connectionType = connection.connectionType
    }

    func clear() {
        accounts = []
        keyVersion = nil
        connectionType = nil
    }

    private func getKeyVersion(using connection: SmartCardConnection) async {
        do {
            let session = try await ManagementSession.session(withConnection: connection)
            self.keyVersion = await session.version.description
        } catch {
            self.error = error
        }
    }

    private func calculateCodes(using connection: SmartCardConnection) async {
        do {
            let session = try await OATHSession.session(withConnection: connection)
            let result = try await session.calculateCodes()
            accounts = result.map { credential, code in
                Account(
                    label: credential.label,
                    code: code?.code,
                    issuer: credential.issuer,
                    type: credential.type
                )
            }
        } catch {
            self.error = error
        }
    }
}
