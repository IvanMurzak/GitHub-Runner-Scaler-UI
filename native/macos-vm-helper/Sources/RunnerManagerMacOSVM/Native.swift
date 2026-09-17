import CryptoKit
import Darwin
import Foundation
import Security
import Virtualization

func hasVirtualizationEntitlement() -> Bool {
    var code: SecCode?
    guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return false }
    guard SecCodeCheckValidity(code, SecCSFlags(), nil) == errSecSuccess else { return false }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else {
        return false
    }
    var information: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
    guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess,
          let values = information as? [String: Any],
          let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
    else {
        return false
    }
    return entitlements["com.apple.security.virtualization"] as? Bool == true
}

func virtualizationIsReady() -> Bool {
    hostArchitecture() == "arm64" && VZVirtualMachine.isSupported
}

func validateTemplateHardwareModel(_ url: URL) throws {
#if arch(arm64)
    let data: Data
    do { data = try Data(contentsOf: url) } catch { throw HelperFailure.rejected("hardware model is invalid") }
    guard let model = VZMacHardwareModel(dataRepresentation: data), model.isSupported else {
        throw HelperFailure.rejected("hardware model is unsupported on this host")
    }
#else
    _ = url
    throw HelperFailure.rejected("macOS guest templates require Apple silicon")
#endif
}

func createMachineIdentifier(at url: URL) throws {
#if arch(arm64)
    let identifier = VZMacMachineIdentifier()
    do {
        try identifier.dataRepresentation.write(to: url, options: [.atomic])
        try setPermissions(url, mode: 0o600)
    } catch {
        throw HelperFailure.degraded("machine identifier creation failed")
    }
#else
    _ = url
    throw HelperFailure.rejected("macOS guest templates require Apple silicon")
#endif
}

func validateResourceConfiguration(cpuMillis: UInt32, memoryMiB: UInt32) throws {
    guard cpuMillis % 1000 == 0 else {
        throw HelperFailure.rejected("CPU limit must resolve to a whole virtual CPU")
    }
    let cpuCount = Int(cpuMillis / 1000)
    let memoryBytes = UInt64(memoryMiB) * 1024 * 1024
    guard cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
          cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount,
          memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
          memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize
    else {
        throw HelperFailure.rejected("requested CPU or memory limit is unsupported")
    }
}

func makeConfiguration(record: EnvironmentRecord, directory: URL) throws -> VZVirtualMachineConfiguration {
#if arch(arm64)
    try validateResourceConfiguration(cpuMillis: record.appliedCpuMillis, memoryMiB: record.appliedMemoryMib)
    let disk = directory.appendingPathComponent(Store.diskName)
    guard logicalSize(disk) == UInt64(record.appliedDiskMib) * 1024 * 1024 else {
        throw HelperFailure.rejected("writable disk limit is not exact")
    }

    let hardwareModelData = try Data(contentsOf: directory.appendingPathComponent(Store.hardwareModelName))
    let machineIdentifierData = try Data(contentsOf: directory.appendingPathComponent(Store.machineIdentifierName))
    guard let hardwareModel = VZMacHardwareModel(dataRepresentation: hardwareModelData),
          hardwareModel.isSupported,
          let machineIdentifier = VZMacMachineIdentifier(dataRepresentation: machineIdentifierData)
    else {
        throw HelperFailure.rejected("virtual Mac identity is invalid")
    }

    let platform = VZMacPlatformConfiguration()
    platform.hardwareModel = hardwareModel
    platform.machineIdentifier = machineIdentifier
    platform.auxiliaryStorage = VZMacAuxiliaryStorage(
        contentsOf: directory.appendingPathComponent(Store.auxiliaryName)
    )

    let attachment = try VZDiskImageStorageDeviceAttachment(
        url: disk,
        readOnly: false,
        cachingMode: .automatic,
        synchronizationMode: .full
    )
    let storage = VZVirtioBlockDeviceConfiguration(attachment: attachment)

    let graphics = VZMacGraphicsDeviceConfiguration()
    graphics.displays = [VZMacGraphicsDisplayConfiguration(
        widthInPixels: 1280,
        heightInPixels: 800,
        pixelsPerInch: 80
    )]

    let network = VZVirtioNetworkDeviceConfiguration()
    network.attachment = VZNATNetworkDeviceAttachment()

    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = platform
    configuration.bootLoader = VZMacOSBootLoader()
    configuration.cpuCount = Int(record.appliedCpuMillis / 1000)
    configuration.memorySize = UInt64(record.appliedMemoryMib) * 1024 * 1024
    configuration.storageDevices = [storage]
    configuration.graphicsDevices = [graphics]
    configuration.keyboards = [VZUSBKeyboardConfiguration()]
    configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
    configuration.networkDevices = [network]
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
    configuration.directorySharingDevices = []
    do { try configuration.validate() } catch {
        throw HelperFailure.rejected("Virtualization.framework rejected the exact resource configuration")
    }
    return configuration
#else
    _ = record
    _ = directory
    throw HelperFailure.rejected("macOS guests require Apple silicon")
#endif
}

func supervisorMatches(_ record: EnvironmentRecord) -> Bool {
    guard let pid = record.supervisorPid, pid > 1, kill(pid, 0) == 0 else { return false }
    var mib = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 0, size < 1024 * 1024 else {
        return false
    }
    var bytes = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, u_int(mib.count), &bytes, &size, nil, 0) == 0 else { return false }
    let arguments = String(decoding: bytes[0..<size], as: UTF8.self)
    return arguments.contains("--internal-supervise") && arguments.contains(record.supervisorToken)
}

func stopEnvironment(store: Store, record original: EnvironmentRecord) throws {
    var record = original
    if !supervisorMatches(record) {
        record.state = .stopped
        record.supervisorPid = nil
        try store.writeRecord(record)
        return
    }
    guard let pid = record.supervisorPid, kill(pid, SIGTERM) == 0 else {
        throw HelperFailure.degraded("VM supervisor could not be stopped")
    }
    let deadline = Date().addingTimeInterval(30)
    while Date() < deadline {
        if !supervisorMatches(record) { break }
        usleep(100_000)
    }
    if supervisorMatches(record) {
        guard kill(pid, SIGKILL) == 0 else { throw HelperFailure.degraded("VM supervisor could not be stopped") }
        let forcedDeadline = Date().addingTimeInterval(5)
        while Date() < forcedDeadline, supervisorMatches(record) { usleep(100_000) }
    }
    guard !supervisorMatches(record) else { throw HelperFailure.degraded("VM supervisor did not exit") }
    record.state = .stopped
    record.supervisorPid = nil
    try store.writeRecord(record)
}

func launchSupervisor(store: Store, record: EnvironmentRecord, jit: inout Data) throws {
    guard record.state == .prepared else {
        throw HelperFailure.rejected("environment is not prepared")
    }
    var starting = record
    starting.state = .booting
    try store.writeRecord(starting)
    let executable = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
    let process = Process()
    process.executableURL = executable
    process.arguments = ["--internal-supervise", record.environmentId, record.supervisorToken]
    var childEnvironment = ProcessInfo.processInfo.environment
    childEnvironment["RUNNER_MANAGER_MACOS_VM_ROOT"] = store.root.path
    process.environment = childEnvironment
    let input = Pipe()
    let status = Pipe()
    process.standardInput = input
    process.standardOutput = status
    process.standardError = FileHandle.nullDevice
    do {
        try process.run()
    } catch {
        starting.state = .stopped
        try? store.writeRecord(starting)
        throw HelperFailure.degraded("VM supervisor launch failed")
    }
    do {
        try input.fileHandleForWriting.write(contentsOf: jit)
        try input.fileHandleForWriting.close()
    } catch {
        process.terminate()
        throw HelperFailure.degraded("JIT handoff to VM supervisor failed")
    }
    jit.resetBytes(in: 0..<jit.count)
    jit.removeAll(keepingCapacity: false)

    let reply = status.fileHandleForReading.readDataToEndOfFile()
    guard reply == Data("READY\n".utf8) else {
        process.terminate()
        throw HelperFailure.degraded("guest bootstrap rejected the JIT handoff")
    }
}

final class VirtualMachineDelegate: NSObject, VZVirtualMachineDelegate {
    let onStop: () -> Void

    init(onStop: @escaping () -> Void) { self.onStop = onStop }

    func guestDidStop(_ virtualMachine: VZVirtualMachine) { onStop() }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) { onStop() }
}

final class Supervisor {
    let store: Store
    var record: EnvironmentRecord
    let directory: URL
    let vmQueue = DispatchQueue(label: "runner-manager-macos-vm.virtual-machine")
    var virtualMachine: VZVirtualMachine?
    var delegate: VirtualMachineDelegate?
    var stopSource: DispatchSourceSignal?

    init(store: Store, record: EnvironmentRecord) throws {
        self.store = store
        self.record = record
        directory = try store.environmentDirectory(record.environmentId)
    }

    func run(jit: inout Data) throws -> Never {
        let deadline = Date().addingTimeInterval(operationTimeout)
        let (manifest, _) = try store.loadTemplate(image: record.image)
        guard manifest.templateDigest == record.templateDigest else {
            throw HelperFailure.rejected("template identity changed")
        }
        let configuration = try makeConfiguration(record: record, directory: directory)
        let vm = VZVirtualMachine(configuration: configuration, queue: vmQueue)
        virtualMachine = vm
        delegate = VirtualMachineDelegate { [weak self] in self?.markStoppedAndExit() }
        vmQueue.sync { vm.delegate = delegate }

        record.state = .booting
        record.supervisorPid = getpid()
        try store.writeRecord(record)
        installStopHandler()
        try requireTime(deadline)
        try start(vm, deadline: deadline)
        let connection = try connect(vm: vm, port: manifest.identity.bootstrapPort, deadline: deadline)
        try sendStart(connection: connection, manifest: manifest, jit: &jit, deadline: deadline)

        record.state = .running
        try store.writeRecord(record)
        try FileHandle.standardOutput.write(contentsOf: Data("READY\n".utf8))
        try FileHandle.standardOutput.close()

        let finalReply = try readReply(connection.fileDescriptor, deadline: nil)
        guard finalReply.protocolVersion == protocolVersion,
              finalReply.status == "exited",
              finalReply.environmentId == record.environmentId,
              finalReply.generation == record.generation,
              let exitCode = finalReply.runnerExitCode
        else {
            throw HelperFailure.degraded("guest bootstrap exit report was invalid")
        }
        record.state = .exited
        record.runnerExitCode = exitCode
        record.supervisorPid = nil
        try store.writeRecord(record)
        connection.close()
        stopVMAndExit()
    }

    private func start(_ vm: VZVirtualMachine, deadline: Date) throws {
        let done = DispatchSemaphore(value: 0)
        var failure: Error?
        vmQueue.async {
            vm.start { result in
                if case let .failure(error) = result { failure = error }
                done.signal()
            }
        }
        guard done.wait(timeout: .now() + max(0, deadline.timeIntervalSinceNow)) == .success, failure == nil else {
            throw HelperFailure.degraded("virtual machine failed to boot")
        }
    }

    private func connect(vm: VZVirtualMachine, port: UInt32, deadline: Date) throws -> VZVirtioSocketConnection {
        guard let socket = vmQueue.sync(execute: { vm.socketDevices.first as? VZVirtioSocketDevice }) else {
            throw HelperFailure.degraded("private guest channel is unavailable")
        }
        while Date() < deadline {
            let done = DispatchSemaphore(value: 0)
            var connected: VZVirtioSocketConnection?
            vmQueue.async {
                socket.connect(toPort: port) { result in
                    if case let .success(connection) = result { connected = connection }
                    done.signal()
                }
            }
            _ = done.wait(timeout: .now() + 5)
            if let connected { return connected }
            sleep(1)
        }
        throw HelperFailure.degraded("guest bootstrap did not open its private channel")
    }

    private func sendStart(
        connection: VZVirtioSocketConnection,
        manifest: TemplateManifest,
        jit: inout Data,
        deadline: Date
    ) throws {
        let archive = directory.appendingPathComponent(Store.runnerArchiveName)
        guard let archiveBytes = logicalSize(archive) else {
            throw HelperFailure.degraded("runner archive is absent")
        }
        let header = GuestStartHeader(
            protocolVersion: protocolVersion,
            command: "start-runner",
            environmentId: record.environmentId,
            generation: record.generation,
            runnerArchiveBytes: archiveBytes,
            runnerArchiveSha256: try sha256(url: archive),
            jitBytes: UInt64(jit.count),
            processLimit: record.appliedProcessLimit,
            processLimitMechanism: manifest.identity.processLimitMechanism
        )
        let headerData = try protocolEncoder.encode(header)
        guard headerData.count <= maximumGuestReplyBytes else {
            throw HelperFailure.degraded("guest request header is too large")
        }
        try writeAll(connection.fileDescriptor, data: Data("RMV1".utf8), deadline: deadline)
        try writeUInt32(connection.fileDescriptor, UInt32(headerData.count), deadline: deadline)
        try writeAll(connection.fileDescriptor, data: headerData, deadline: deadline)
        try streamFile(archive, to: connection.fileDescriptor, deadline: deadline)
        try writeAll(connection.fileDescriptor, data: jit, deadline: deadline)
        jit.resetBytes(in: 0..<jit.count)
        jit.removeAll(keepingCapacity: false)

        let reply = try readReply(connection.fileDescriptor, deadline: deadline)
        guard reply.protocolVersion == protocolVersion,
              reply.status == "accepted",
              reply.environmentId == record.environmentId,
              reply.generation == record.generation,
              reply.appliedProcessLimit == record.appliedProcessLimit,
              reply.processLimitMechanism == "rlimit_nproc_dedicated_uid",
              reply.runnerUidExclusive,
              reply.runnerPid != nil
        else {
            throw HelperFailure.degraded("guest bootstrap did not attest the process limit")
        }
    }

    private func installStopHandler() {
        signal(SIGTERM, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: DispatchQueue.global())
        source.setEventHandler { [weak self] in self?.markStoppedAndExit() }
        source.resume()
        stopSource = source
    }

    private func markStoppedAndExit() -> Never {
        record.state = .stopped
        record.supervisorPid = nil
        try? store.writeRecord(record)
        stopVMAndExit()
    }

    private func stopVMAndExit() -> Never {
        guard let vm = virtualMachine else { Darwin.exit(0) }
        let done = DispatchSemaphore(value: 0)
        vmQueue.async {
            if vm.canStop {
                vm.stop { _ in done.signal() }
            } else {
                done.signal()
            }
        }
        _ = done.wait(timeout: .now() + 20)
        Darwin.exit(0)
    }
}

func writeUInt32(_ fd: Int32, _ value: UInt32, deadline: Date) throws {
    var bigEndian = value.bigEndian
    try withUnsafeBytes(of: &bigEndian) { bytes in
        try writeRaw(fd, bytes: bytes, deadline: deadline)
    }
}

func writeAll(_ fd: Int32, data: Data, deadline: Date) throws {
    try data.withUnsafeBytes { bytes in try writeRaw(fd, bytes: bytes, deadline: deadline) }
}

func writeRaw(_ fd: Int32, bytes: UnsafeRawBufferPointer, deadline: Date) throws {
    var offset = 0
    while offset < bytes.count {
        var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&descriptor, 1, try pollTimeout(deadline)) > 0 else {
            throw HelperFailure.degraded("private guest channel timed out")
        }
        let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
        guard count > 0 else { throw HelperFailure.degraded("private guest channel closed") }
        offset += count
    }
}

func streamFile(_ url: URL, to fd: Int32, deadline: Date) throws {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    while true {
        let data = try handle.read(upToCount: 1024 * 1024) ?? Data()
        if data.isEmpty { return }
        try writeAll(fd, data: data, deadline: deadline)
    }
}

func readReply(_ fd: Int32, deadline: Date?) throws -> GuestReply {
    let sizeData = try readExact(fd, count: 4, deadline: deadline)
    let size = sizeData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    guard size > 0, size <= maximumGuestReplyBytes else {
        throw HelperFailure.degraded("guest reply exceeded its bound")
    }
    let data = try readExact(fd, count: Int(size), deadline: deadline)
    do { return try protocolDecoder.decode(GuestReply.self, from: data) } catch {
        throw HelperFailure.degraded("guest reply was invalid")
    }
}

func readExact(_ fd: Int32, count: Int, deadline: Date?) throws -> Data {
    var result = Data(count: count)
    var offset = 0
    try result.withUnsafeMutableBytes { bytes in
        while offset < count {
            var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let timeout = try deadline.map(pollTimeout) ?? -1
            guard poll(&descriptor, 1, timeout) > 0 else {
                throw HelperFailure.degraded("private guest channel timed out")
            }
            let amount = Darwin.read(fd, bytes.baseAddress!.advanced(by: offset), count - offset)
            guard amount > 0 else { throw HelperFailure.degraded("private guest channel closed") }
            offset += amount
        }
    }
    return result
}

func requireTime(_ deadline: Date) throws {
    guard deadline.timeIntervalSinceNow > 0 else {
        throw HelperFailure.degraded("VM start operation timed out")
    }
}

func pollTimeout(_ deadline: Date) throws -> Int32 {
    try requireTime(deadline)
    return Int32(min(Double(Int32.max), max(1, deadline.timeIntervalSinceNow * 1000)))
}
