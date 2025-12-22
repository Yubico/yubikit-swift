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

// MARK: - Interface (Internal Transport Abstraction)

extension CTAP2.Session {
    /// Internal actor that abstracts over the underlying transport (HID or SmartCard).
    ///
    /// This allows `CTAP2.Session` to be a concrete type while supporting multiple transports.
    internal actor Interface {
        enum Kind {
            case ccid(SmartCardInterface<CTAP2.SessionError>)
            case hid(FIDOInterface<CTAP2.SessionError>)
        }

        let kind: Kind

        init(interface: SmartCardInterface<CTAP2.SessionError>) {
            self.kind = .ccid(interface)
        }

        init(interface: FIDOInterface<CTAP2.SessionError>) {
            self.kind = .hid(interface)
        }
    }
}

// MARK: - CBORInterface Conformance

extension CTAP2.Session.Interface: CBORInterface {
    typealias Error = CTAP2.SessionError

    var version: Version {
        get async {
            switch kind {
            case let .ccid(i):
                return await i.version
            case let .hid(i):
                return await i.version
            }
        }
    }

    var maxMsgSize: Int {
        get async {
            switch kind {
            case let .ccid(i):
                return await i.maxMsgSize
            case let .hid(i):
                return await i.maxMsgSize
            }
        }
    }

    func setMaxMsgSize(_ size: Int) async {
        switch kind {
        case let .ccid(i):
            await i.setMaxMsgSize(size)
        case let .hid(i):
            await i.setMaxMsgSize(size)
        }
    }

    func send<I: In, O: Out>(
        command: CTAP2.Command,
        payload: I
    ) async -> CTAP2.StatusStream<O> {
        switch kind {
        case let .ccid(i):
            return await i.send(command: command, payload: payload)
        case let .hid(i):
            return await i.send(command: command, payload: payload)
        }
    }

    func send<I: In>(
        command: CTAP2.Command,
        payload: I
    ) async -> CTAP2.StatusStream<Void> {
        switch kind {
        case let .ccid(i):
            return await i.send(command: command, payload: payload)
        case let .hid(i):
            return await i.send(command: command, payload: payload)
        }
    }
}
