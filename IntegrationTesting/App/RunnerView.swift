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

import SwiftUI
import YubiKit
import YubiKitIntegrationScenarios

struct RunnerView: View {
    @StateObject private var model = RunnerViewModel()
    @State private var selection: SidebarItem?

    #if os(macOS)
    @State private var showInspector = true
    #else
    @State private var showInspector = false
    #endif

    @State private var collapsedSuites: Set<Scenario.Suite> = []

    private enum SidebarItem: Hashable {
        case backend
        case scenario(Scenario)
    }

    var body: some View {
        NavigationStack {
            scenarioList
                .navigationTitle("")
                .toolbarTitleDisplayMode(.inline)
                .safeAreaInset(edge: .top) { ControlBar(model: model) }
                .safeAreaInset(edge: .bottom) { CountsBar(model: model) }
                .toolbar { toolbar }
                .inspector(isPresented: $showInspector) {
                    inspectorContent
                        .inspectorColumnWidth(min: 320, ideal: 400, max: 560)
                }
        }
        .overlay(alignment: .top) {
            ZStack(alignment: .top) {
                if let prompt = model.touchPrompt {
                    TouchBanner(prompt: prompt)
                }
            }
            .animation(.snappy, value: model.touchPrompt)
        }
        .onChange(of: selection) { _, new in
            if new != nil { showInspector = true }
        }
        .alert("No YubiKey available", isPresented: backendAlertBinding, presenting: model.backendAlert) { _ in
            Button("OK", role: .cancel) {}
        } message: { alert in
            Text(alert.message)
        }
    }

    private var backendAlertBinding: Binding<Bool> {
        Binding(
            get: { model.backendAlert != nil },
            set: { if !$0 { model.backendAlert = nil } }
        )
    }

    private var scenarioList: some View {
        ScrollViewReader { proxy in
            List(selection: $selection) {
                ForEach(model.visibleSuites, id: \.self) { suite in
                    Section {
                        if !collapsedSuites.contains(suite) {
                            ForEach(model.visibleScenarios(in: suite)) { scenario in
                                ScenarioRow(
                                    scenario: scenario,
                                    result: model.result(for: scenario),
                                    skipReason: model.skipReason(scenario)
                                )
                                .tag(SidebarItem.scenario(scenario))
                            }
                        }
                    } header: {
                        SuiteHeader(model: model, suite: suite, isCollapsed: collapsedSuites.contains(suite)) {
                            withAnimation(.snappy) {
                                if collapsedSuites.contains(suite) {
                                    collapsedSuites.remove(suite)
                                } else {
                                    collapsedSuites.insert(suite)
                                }
                            }
                        }
                        .listRowInsets(EdgeInsets())
                    }
                }
            }
            .listStyle(.inset)
            .onChange(of: model.runningScenario) { _, scenario in
                guard let scenario else { return }
                withAnimation { proxy.scrollTo(scenario.id, anchor: .center) }
            }
        }
    }

    @ViewBuilder private var inspectorContent: some View {
        switch selection {
        case .scenario(let scenario): ScenarioDetail(model: model, scenario: scenario)
        case .backend, .none: BackendInfoView(model: model)
        }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Menu {
                #if os(macOS)
                Section {
                    Button {
                        selection = .backend
                        showInspector = true
                    } label: {
                        Label("Backend & host info", systemImage: "gearshape.2")
                    }
                }
                #endif
                Section("Secure channel") {
                    Picker("Secure channel", selection: $model.secureChannel) {
                        Text("None").tag(SecureChannelPolicy.none)
                        Text("Automatic (SCP11b → SCP03)").tag(SecureChannelPolicy.automatic)
                        Text("SCP11b").tag(SecureChannelPolicy.scp11b)
                        Text("SCP03").tag(SecureChannelPolicy.scp03)
                    }
                    .pickerStyle(.inline)
                    .disabled(model.isRunning || model.providerCaps?.supportsSecureChannel != true)
                }
                Section {
                    Button(role: .destructive) {
                        model.resetResults()
                    } label: {
                        Label("Reset results", systemImage: "arrow.counterclockwise")
                    }
                    .disabled(model.isRunning)
                }
            } label: {
                Label("More", systemImage: "ellipsis.circle")
            }

            #if os(macOS)
            Button {
                showInspector.toggle()
            } label: {
                Label("Inspector", systemImage: "sidebar.right")
            }
            .help("Show or hide the detail inspector")
            #else
            Button {
                selection = .backend
                showInspector = true
            } label: {
                Label("Backend & host info", systemImage: "info.circle")
            }
            #endif
        }
    }
}

// MARK: - Control bar (shared across platforms)

private struct ControlBar: View {
    @ObservedObject var model: RunnerViewModel

    private var filterActive: Bool { model.failuresOnly }

    var body: some View {
        HStack(spacing: 12) {
            if model.availableBackends.count > 1 {
                Picker("Backend", selection: $model.backend) {
                    ForEach(model.availableBackends) { Label($0.rawValue, systemImage: $0.systemImage).tag($0) }
                }
                .pickerStyle(.menu)
                .fixedSize()
                .labelsHidden()
                .disabled(model.isRunning)
                .help("Run scenarios over a wired connection or NFC")
            }

            if model.isRunning {
                Button(role: .cancel) {
                    model.cancel()
                } label: {
                    Label("Cancel", systemImage: "stop.fill")
                }
                .buttonStyle(.bordered)
            } else {
                Button {
                    model.runAll()
                } label: {
                    Label("Run All", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
            }

            if model.isProbing {
                ProgressView().controlSize(.small)
            } else {
                Button {
                    model.probeDevice()
                } label: {
                    #if os(iOS)
                    Label("Check", systemImage: "sensor.tag.radiowaves.forward").labelStyle(.iconOnly)
                    #else
                    Label("Check", systemImage: "sensor.tag.radiowaves.forward")
                    #endif
                }
                .buttonStyle(.bordered)
                .disabled(model.isRunning)
                .help("Read the attached key's info so the list can gate on its capabilities")
            }

            Spacer(minLength: 0)

            filterMenu
        }
        .lineLimit(1)
        .padding(.horizontal, 16).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.bar)
    }

    @ViewBuilder private var filterMenu: some View {
        let icon = filterActive ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle"
        Menu {
            Section("Show") {
                Toggle(isOn: $model.failuresOnly) { Label("Failures only", systemImage: "xmark.circle") }
            }
            Section {
                Button {
                    model.runVisible()
                } label: {
                    Label("Run filtered", systemImage: "play")
                }
                .disabled(model.isRunning)
            }
        } label: {
            #if os(iOS)
            Label("Filter", systemImage: icon).labelStyle(.iconOnly)
            #else
            Label("Filter", systemImage: icon)
            #endif
        }
        .fixedSize()
        .tint(filterActive ? .accentColor : .secondary)
        .help("Filter which scenarios are shown")
    }
}

// MARK: - List pieces

private struct SuiteHeader: View {
    @ObservedObject var model: RunnerViewModel
    let suite: Scenario.Suite
    let isCollapsed: Bool
    let toggleCollapsed: () -> Void

    var body: some View {
        let counts = model.suiteCounts(suite)
        HStack(spacing: 8) {
            Button(action: toggleCollapsed) {
                HStack(spacing: 8) {
                    Image(systemName: "chevron.right")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(isCollapsed ? 0 : 90))
                    Text(suite.displayName).font(.headline)
                    Spacer()
                    if counts.failed > 0 { Text("\(counts.failed)✗").font(.subheadline).foregroundStyle(.red) }
                    if counts.passed > 0 { Text("\(counts.passed)✓").font(.subheadline).foregroundStyle(.green) }
                    Text("\(counts.total)").font(.subheadline).foregroundStyle(.secondary).monospacedDigit()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(suite.displayName) suite, \(isCollapsed ? "collapsed" : "expanded")")

            Button {
                model.runSuite(suite)
            } label: {
                Image(systemName: "play.fill")
            }
            .buttonStyle(.borderless)
            .disabled(model.isRunning)
            .help("Run the \(suite.displayName) suite")
        }
        .textCase(nil)
        .padding(.horizontal, 16)
        .padding(.vertical, 6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.bar)
    }
}

private struct ScenarioRow: View {
    let scenario: Scenario
    let result: Scenario.Result?
    let skipReason: String?

    var body: some View {
        HStack(spacing: 12) {
            StatusGlyph(status: result?.status, willSkip: skipReason != nil)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(scenario.name).lineLimit(2)
                if let skipReason {
                    Label(skipReason, systemImage: "minus.circle")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if let duration = result?.duration, duration > .zero, result?.status != .running {
                Text(format(duration)).font(.callout).foregroundStyle(.secondary).monospacedDigit()
            }
        }
        .padding(.vertical, 4)
        .opacity(skipReason != nil ? 0.5 : 1)
    }
}

private struct CountsBar: View {
    @ObservedObject var model: RunnerViewModel

    var body: some View {
        HStack(spacing: 10) {
            tally("\(model.passedCount)", "checkmark.circle.fill", .green)
            tally("\(model.failedCount)", "xmark.circle.fill", .red)
            tally("\(model.skippedCount)", "minus.circle.fill", .orange)
            if !model.isRunning {
                Text("/ \(model.totalCount)").font(.callout).foregroundStyle(.secondary).monospacedDigit()
                    .fixedSize()
            }
            Spacer()
            if model.isRunning {
                ProgressView(value: Double(model.ranCount), total: Double(max(model.runTotal, 1)))
                    .frame(width: 80)
                Text("\(model.ranCount)/\(model.runTotal)")
                    .font(.callout).monospacedDigit().foregroundStyle(.secondary)
                    .lineLimit(1).fixedSize()
            } else {
                if model.secureChannel != .none {
                    Label(secureChannelLabel(model.secureChannel), systemImage: "lock.shield")
                        .font(.callout).foregroundStyle(.teal).lineLimit(1)
                        .help("CCID scenarios run over a secure channel")
                }
                if let device = model.probedDevice {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.seal")
                        Text(verbatim: "v\(device.version) · \(device.serialNumber)")
                    }
                    .font(.callout).foregroundStyle(.secondary).lineLimit(1)
                } else if model.probeError != nil {
                    Label("no device", systemImage: "exclamationmark.circle")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(.bar)
    }

    private func tally(_ value: String, _ symbol: String, _ color: Color) -> some View {
        Label(value, systemImage: symbol).font(.callout).foregroundStyle(color).monospacedDigit().fixedSize()
    }
}

// MARK: - Inspector: scenario detail

private struct ScenarioDetail: View {
    @ObservedObject var model: RunnerViewModel
    let scenario: Scenario

    var body: some View {
        let result = model.result(for: scenario)
        let skipReason = model.skipReason(scenario)
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    StatusGlyph(status: result?.status, willSkip: skipReason != nil)
                    Text(scenario.name).font(.title2).fontWeight(.semibold)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                Text(scenario.id).font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Button {
                    model.runOne(scenario)
                } label: {
                    Label("Run", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(model.isRunning || skipReason != nil)

                if let skipReason {
                    Label("Will skip on \(model.backend.rawValue): \(skipReason)", systemImage: "minus.circle")
                        .font(.callout).foregroundStyle(.orange)
                }

                let badges = requirementBadges(scenario)
                if !badges.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Requirements").font(.headline)
                        FlowLayout(spacing: 6) {
                            ForEach(badges, id: \.label) { Chip(text: $0.label, color: $0.color) }
                        }
                    }
                }

                if let thrown = result?.thrownError {
                    GroupBox("Error") {
                        Text(thrown).font(.system(.callout, design: .monospaced)).frame(
                            maxWidth: .infinity,
                            alignment: .leading
                        )
                        .textSelection(.enabled)
                    }
                }
                if let failures = result?.failures, !failures.isEmpty {
                    GroupBox("Failures (\(failures.count))") {
                        VStack(alignment: .leading, spacing: 10) {
                            ForEach(failures) { failure in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(failure.message)
                                    Text(failure.location.description).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                    }
                }
                let logLines = result?.logs ?? []
                if !logLines.isEmpty {
                    GroupBox("Log") {
                        ScrollViewReader { logProxy in
                            ScrollView {
                                VStack(alignment: .leading, spacing: 2) {
                                    ForEach(Array(logLines.enumerated()), id: \.offset) {
                                        Text($1).font(.system(.caption, design: .monospaced)).id($0)
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .textSelection(.enabled)
                            }
                            .frame(maxHeight: 240)
                            .onChange(of: logLines.count) { _, count in
                                withAnimation { logProxy.scrollTo(count - 1, anchor: .bottom) }
                            }
                        }
                    }
                }
                if let duration = result?.duration, duration > .zero, result?.status != .running {
                    Text("Finished in \(format(duration))").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(20)
        }
    }
}

// MARK: - Inspector: backend info

private struct BackendInfoView: View {
    @ObservedObject var model: RunnerViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("Backend").font(.title2).bold()

                GroupBox("This host") {
                    VStack(alignment: .leading, spacing: 8) {
                        infoRow("Platform", platformName)
                        infoRow("Transport", model.backend.rawValue)
                        if let transport = model.providerTransport {
                            infoRow("Gating transport", transportName(transport))
                        }
                        if let ctap2 = model.ctap2Transport {
                            infoRow("CTAP2", ctap2Name(ctap2))
                        }
                        if let caps = model.providerCaps {
                            FlowLayout(spacing: 6) {
                                ForEach(hostChips(caps), id: \.self) { Chip(text: $0, color: .blue) }
                            }
                            .padding(.top, 2)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                GroupBox("Connected key") {
                    connectedKey.frame(maxWidth: .infinity, alignment: .leading)
                }

                Text("Select a scenario from the list to see its requirements and run it.")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
            }
            .padding(20)
        }
    }

    @ViewBuilder private var connectedKey: some View {
        if let device = model.probedDevice {
            VStack(alignment: .leading, spacing: 8) {
                infoRow("Firmware", "\(device.version)")
                infoRow("Serial", "\(device.serialNumber)")
                infoRow("Form factor", "\(device.formFactor)")
                infoRow("FIPS", device.isFIPS ? "yes" : "no")
                if let transport = model.providerTransport {
                    let apps = enabledApps(device, over: transport)
                    if !apps.isEmpty {
                        Text("Enabled applications").font(.subheadline).foregroundStyle(.secondary)
                        FlowLayout(spacing: 6) {
                            ForEach(apps, id: \.self) { Chip(text: $0, color: .green) }
                        }
                    }
                }
            }
        } else if let error = model.probeError {
            Label(error, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.secondary)
        } else {
            Label(
                "Tap Check in the controls to read the attached key.",
                systemImage: "sensor.tag.radiowaves.forward"
            )
            .font(.callout).foregroundStyle(.secondary)
        }
    }

    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).monospacedDigit()
        }
        .font(.body)
    }

    private var platformName: String {
        #if os(macOS)
        return "macOS"
        #else
        return "iOS"
        #endif
    }

    private func transportName(_ transport: DeviceTransport) -> String {
        switch transport {
        case .usb: return "USB"
        case .nfc: return "NFC"
        }
    }

    private func ctap2Name(_ transport: CTAP2Transport) -> String {
        switch transport {
        case .fido: return "FIDO HID"
        case .ccid: return "CCID"
        }
    }

    private func hostChips(_ caps: ProviderCapabilities) -> [String] {
        var chips: [String] = []
        if caps.hasFIDO { chips.append("FIDO HID") }
        if caps.supportsSecureChannel { chips.append("SCP") }
        if caps.isVirtual { chips.append("virtual") }
        return chips
    }

    private func enabledApps(_ device: DeviceInfo, over transport: DeviceTransport) -> [String] {
        let apps: [(Capability, String)] = [
            (.otp, "OTP"), (.u2f, "U2F"), (.openPGP, "OpenPGP"), (.piv, "PIV"),
            (.oath, "OATH"), (.hsmAuth, "HSMAuth"), (.fido2, "FIDO2"),
        ]
        return apps.filter { device.config.isApplicationEnabled($0.0, over: transport) }.map { $0.1 }
    }
}

// MARK: - Small components

private struct StatusGlyph: View {
    let status: Scenario.Result.Status?
    var willSkip: Bool = false

    var body: some View {
        Group {
            switch status {
            case .passed: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
            case .failed, .errored: Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
            case .skipped: Image(systemName: "minus.circle.fill").foregroundStyle(.orange)
            case .backendUnavailable: Image(systemName: "bolt.slash.fill").foregroundStyle(.red)
            case .running: ProgressView().controlSize(.small)
            case .none:
                Image(systemName: willSkip ? "circle.dotted" : "circle")
                    .foregroundStyle(willSkip ? Color.orange.opacity(0.6) : Color.secondary)
            }
        }
        .imageScale(.large)
    }
}

private struct Chip: View {
    let text: String
    var color: Color = .secondary

    var body: some View {
        Text(text)
            .font(.caption)
            .padding(.horizontal, 9).padding(.vertical, 4)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }
}

private struct TouchBanner: View {
    let prompt: String
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "hand.tap")
            Text(prompt)
            Spacer(minLength: 0)
        }
        .font(.callout.weight(.semibold))
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity)
        .background(.yellow.opacity(0.95))
        .overlay(alignment: .bottom) { Divider() }
        .transition(.move(edge: .top))
    }
}

private struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > maxWidth, x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        return CGSize(width: maxWidth.isFinite ? maxWidth : x, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            view.place(at: CGPoint(x: x, y: y), anchor: .topLeading, proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

// MARK: - Helpers

private func format(_ duration: Duration) -> String {
    let ms = Double(duration.components.seconds) * 1000 + Double(duration.components.attoseconds) / 1e15
    return ms >= 1000 ? String(format: "%.1f s", ms / 1000) : String(format: "%.0f ms", ms)
}

private func secureChannelLabel(_ policy: SecureChannelPolicy) -> String {
    switch policy {
    case .none: return "plaintext"
    case .automatic: return "SCP (auto)"
    case .scp11b: return "SCP11b"
    case .scp03: return "SCP03"
    }
}

private func requirementBadges(_ scenario: Scenario) -> [(label: String, color: Color)] {
    let requirements = scenario.requirements
    var badges: [(label: String, color: Color)] = []
    for capability in requirements.capabilities.map({ "\($0)".uppercased() }).sorted() {
        badges.append((label: capability, color: .blue))
    }
    if let minVersion = requirements.minVersion { badges.append((label: "≥ \(minVersion)", color: .secondary)) }
    if let transports = requirements.transports {
        badges.append((label: transports.map { "\($0)".uppercased() }.sorted().joined(separator: "/"), color: .purple))
    }
    if requirements.requiresBio { badges.append((label: "Bio", color: .pink)) }
    if requirements.excludesBio { badges.append((label: "non-Bio", color: .pink)) }
    if requirements.requiresSCP { badges.append((label: "SCP", color: .teal)) }
    if requirements.requiresFIDOTransport { badges.append((label: "FIDO HID", color: .purple)) }
    if requirements.requiresLightning { badges.append((label: "Lightning", color: .purple)) }
    if requirements.requiresRealHardware { badges.append((label: "real hardware", color: .orange)) }
    return badges
}
