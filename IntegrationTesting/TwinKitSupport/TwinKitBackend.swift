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
import TwinKit

public enum TwinKitSupportError: Error, Sendable {
    case unavailable(String)
    case connectionLost
    case invalidHIDReportLength(Int)
    case noHIDReport
}

public enum TwinKitSmartCardTransport: Sendable {
    case usb
    case nfc

    fileprivate var tag: UInt8 {
        switch self {
        case .usb: TwinDevice.Tag.ccidApduUSB
        case .nfc: TwinDevice.Tag.ccidApduNFC
        }
    }
}

/// Owns the process-local TwinKit device shared by simulator and test adapters.
public actor TwinKitBackend {
    public static let shared = TwinKitBackend()

    private static let environmentProfileConfiguration: (profile: DeviceProfile?, error: String?) = {
        guard let value = ProcessInfo.processInfo.environment["YUBIKIT_ENABLE_TWINKIT"],
            !value.isEmpty, value != "1"
        else { return (nil, nil) }
        guard let profile = DeviceProfile(rawValue: value) else {
            return (nil, "invalid YUBIKIT_ENABLE_TWINKIT profile '\(value)'")
        }
        return (profile, nil)
    }()

    /// The profile read from `YUBIKIT_ENABLE_TWINKIT`; `"1"` selects the default profile.
    public static let environmentProfile = environmentProfileConfiguration.profile

    /// A configuration error when `YUBIKIT_ENABLE_TWINKIT` names an unknown profile.
    public static let environmentProfileConfigurationError = environmentProfileConfiguration.error

    private var device: TwinDevice?
    private let profile: DeviceProfile?

    public init(profile: DeviceProfile? = TwinKitBackend.environmentProfile) {
        self.profile = profile
    }

    public func isAvailable() -> Bool {
        do {
            _ = try loadDevice()
            return true
        } catch {
            return false
        }
    }

    public func openSmartCard(
        transport: TwinKitSmartCardTransport
    ) throws(TwinKitSupportError) -> TwinKitSmartCardChannel {
        let device = try loadDevice()
        device.deselect()
        return TwinKitSmartCardChannel(backend: self, transport: transport)
    }

    public func openFIDO() throws(TwinKitSupportError) -> TwinKitFIDOChannel {
        _ = try loadDevice()
        return TwinKitFIDOChannel(backend: self)
    }

    fileprivate func dispatch(tag: UInt8, payload: Data = Data()) throws(TwinKitSupportError) -> Data {
        try loadDevice().dispatch(tag: tag, payload: payload)
    }

    private func loadDevice() throws(TwinKitSupportError) -> TwinDevice {
        if let device { return device }
        do {
            let device = try EmbeddedTwin.shared.makeDevice(profile: profile)
            self.device = device
            return device
        } catch {
            throw .unavailable(String(describing: error))
        }
    }
}

public final class TwinKitSmartCardChannel: @unchecked Sendable {
    private let backend: TwinKitBackend
    private let transport: TwinKitSmartCardTransport
    private let lifecycle = TwinKitConnectionLifecycle()

    fileprivate init(backend: TwinKitBackend, transport: TwinKitSmartCardTransport) {
        self.backend = backend
        self.transport = transport
    }

    public func send(_ data: Data) async throws(TwinKitSupportError) -> Data {
        guard !lifecycle.isClosed else { throw .connectionLost }
        return try await backend.dispatch(tag: transport.tag, payload: data)
    }

    public func close(error: Error?) {
        lifecycle.close(error: error)
    }

    public func waitUntilClosed() async -> Error? {
        await lifecycle.waitUntilClosed()
    }
}

public final class TwinKitFIDOChannel: @unchecked Sendable {
    public let mtu = 64

    private let backend: TwinKitBackend
    private let lifecycle = TwinKitConnectionLifecycle()

    fileprivate init(backend: TwinKitBackend) {
        self.backend = backend
    }

    public func send(_ report: Data) async throws(TwinKitSupportError) {
        guard !lifecycle.isClosed else { throw .connectionLost }
        guard report.count == mtu else { throw .invalidHIDReportLength(report.count) }
        _ = try await backend.dispatch(tag: TwinDevice.Tag.ctapHIDWrite, payload: report)
    }

    public func receive() async throws(TwinKitSupportError) -> Data {
        guard !lifecycle.isClosed else { throw .connectionLost }
        let report = try await backend.dispatch(tag: TwinDevice.Tag.ctapHIDRead)
        guard report.count == mtu else { throw .noHIDReport }
        return report
    }

    public func close(error: Error?) {
        lifecycle.close(error: error)
    }

    public func waitUntilClosed() async -> Error? {
        await lifecycle.waitUntilClosed()
    }
}

private final class TwinKitConnectionLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    private var closeError: Error?
    private var waiters: [CheckedContinuation<Error?, Never>] = []

    var isClosed: Bool {
        lock.withLock { closed }
    }

    func close(error: Error?) {
        let waiters = lock.withLock { () -> [CheckedContinuation<Error?, Never>] in
            guard !closed else { return [] }
            closed = true
            closeError = error
            defer { self.waiters.removeAll() }
            return self.waiters
        }
        waiters.forEach { $0.resume(returning: error) }
    }

    func waitUntilClosed() async -> Error? {
        await withCheckedContinuation { continuation in
            let error = lock.withLock { () -> Error?? in
                if closed { return .some(closeError) }
                waiters.append(continuation)
                return nil
            }
            if let error { continuation.resume(returning: error) }
        }
    }
}
