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

// Shared by a connection handle and its manager. All mutable state is confined
// to the session queue; handles never access it outside that queue.
final class NFCConnectionLifecycle: @unchecked Sendable {
    typealias Completion = @Sendable (Result<Data, Error>) -> Void

    private let queue: DispatchQueue
    private var pending: [UUID: Completion] = [:]
    private var isClosed = false
    private var cancellationError: SmartCardConnectionError?

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    var closedError: SmartCardConnectionError {
        dispatchPrecondition(condition: .onQueue(queue))
        return cancellationError ?? .connectionLost
    }

    func register(_ completion: @escaping Completion) -> UUID? {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !isClosed else {
            completion(.failure(closedError))
            return nil
        }
        let id = UUID()
        pending[id] = completion
        return id
    }

    func complete(_ id: UUID, with result: Result<Data, Error>) {
        dispatchPrecondition(condition: .onQueue(queue))
        pending.removeValue(forKey: id)?(result)
    }

    func invalidate(error: Error?) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !isClosed else { return }
        isClosed = true
        if let error = error as? SmartCardConnectionError {
            switch error {
            case .cancelled, .cancelledByUser: cancellationError = error
            default: break
            }
        }
        let completions = pending.values
        pending.removeAll()
        for completion in completions {
            completion(.failure(error ?? SmartCardConnectionError.connectionLost))
        }
    }

    static func invalidationError(_ error: Error, userCancelled: Bool, closing: Bool) -> Error? {
        guard userCancelled else { return error }
        return closing ? nil : SmartCardConnectionError.cancelledByUser
    }
}
