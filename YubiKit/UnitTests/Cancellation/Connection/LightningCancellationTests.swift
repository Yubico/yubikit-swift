// Copyright Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

#if os(iOS)

import Foundation
import Testing

@testable import YubiKit

@Suite("Lightning connection cancellation", .timeLimit(.minutes(1)))
struct LightningCancellationTests {

    @Test("A pre-cancelled connection attempt does not start accessory work")
    func preCancelledConnectionDoesNotStart() async {
        let accessoryManager = BlockingLightningAccessoryManager()
        let manager = LightningConnectionManager(accessoryManager: accessoryManager)

        let connectionAttempt = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await manager.connect()
        }

        do {
            _ = try await connectionAttempt.value
            Issue.record("A pre-cancelled connection attempt succeeded")
        } catch SmartCardConnectionError.cancelled {
        } catch {
            Issue.record("Unexpected connection error: \(error)")
        }

        #expect(await accessoryManager.connectToCurrentDevicesCount == 0)
        #expect(await accessoryManager.startMonitoringCount == 0)
    }

    @Test("A late accessory callback during cancellation cleanup is closed")
    func lateAccessoryCallbackIsClosedDuringCleanup() async throws {
        let accessoryManager = BlockingLightningAccessoryManager()
        let manager = LightningConnectionManager(accessoryManager: accessoryManager)

        let connectionAttempt = Task { try await manager.connect() }
        try await accessoryManager.firstMonitoringStarted.value()

        connectionAttempt.cancel()
        try await accessoryManager.stopMonitoringStarted.value()

        await manager.accessoryDidConnect(connectionID: 7)
        #expect(await accessoryManager.cleanedConnectionIDs == [7])

        do {
            _ = try await manager.connect()
            Issue.record("A new connection started before cancelled setup cleanup finished")
        } catch SmartCardConnectionError.busy {
        } catch {
            Issue.record("Unexpected error while cleanup was in progress: \(error)")
        }

        await accessoryManager.finishStoppingMonitoring()
        do {
            _ = try await connectionAttempt.value
            Issue.record("Cancelled connection setup returned successfully")
        } catch SmartCardConnectionError.cancelled {
        } catch {
            Issue.record("Unexpected connection error: \(error)")
        }

        await accessoryManager.connectOnNextMonitoring(manager, connectionID: 42)
        #expect(try await manager.connect() == 42)
    }
}

private actor BlockingLightningAccessoryManager: LightningAccessoryManaging {
    let firstMonitoringStarted = Promise<Void>()
    let stopMonitoringStarted = Promise<Void>()
    private let finishStopMonitoring = Promise<Void>()

    private(set) var cleanedConnectionIDs: [LightningConnectionID] = []
    private(set) var connectToCurrentDevicesCount = 0
    private(set) var startMonitoringCount = 0
    private var onNextMonitoring: (@Sendable () async -> Void)?

    func connectToCurrentDevices() async {
        connectToCurrentDevicesCount += 1
    }

    func startMonitoring() async {
        startMonitoringCount += 1
        if startMonitoringCount == 1 {
            await firstMonitoringStarted.fulfill(())
        }
        if let onNextMonitoring {
            self.onNextMonitoring = nil
            await onNextMonitoring()
        }
    }

    func connectOnNextMonitoring(_ manager: LightningConnectionManager, connectionID: LightningConnectionID) {
        onNextMonitoring = { await manager.accessoryDidConnect(connectionID: connectionID) }
    }

    func stopMonitoring() async {
        await stopMonitoringStarted.fulfill(())
        _ = try? await finishStopMonitoring.value()
    }

    func finishStoppingMonitoring() async {
        await finishStopMonitoring.fulfill(())
    }

    func cleanupConnection(id: LightningConnectionID) async {
        cleanedConnectionIDs.append(id)
    }

    func transmit(id: LightningConnectionID, data: Data) async throws(SmartCardConnectionError) -> Data {
        throw .connectionLost
    }
}

#endif
