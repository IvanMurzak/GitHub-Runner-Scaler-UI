import Darwin
import Foundation

struct Store {
    static let metadataName = "metadata.json"
    static let manifestName = "manifest.json"
    static let diskName = "Disk.img"
    static let auxiliaryName = "AuxiliaryStorage"
    static let hardwareModelName = "HardwareModel"
    static let machineIdentifierName = "MachineIdentifier"
    static let runnerArchiveName = "runner.tar"

    let root: URL
    let templates: URL
    let environments: URL

    init(environment: [String: String] = ProcessInfo.processInfo.environment) throws {
        let configured = environment["RUNNER_MANAGER_MACOS_VM_ROOT"]
            ?? "/Library/Application Support/io.github.IvanMurzak.runner-manager/macos-vm-helper"
        guard configured.hasPrefix("/") else {
            throw HelperFailure.rejected("helper store must be an absolute path")
        }
        root = URL(fileURLWithPath: configured, isDirectory: true).standardizedFileURL
        templates = root.appendingPathComponent("templates", isDirectory: true)
        environments = root.appendingPathComponent("environments", isDirectory: true)
        do {
            try ensureDirectory(root)
            try ensureDirectory(templates)
            try ensureDirectory(environments)
        } catch {
            // A boot LaunchDaemon can have a different macOS volume-access
            // context from the interactive operator who registered a template.
            // Preserve that distinction through the helper protocol instead of
            // falling through main's generic exit-1 failure.
            throw sanitized(error, "helper store initialization failed")
        }
    }

    func templateDirectory(_ digest: String) -> URL {
        templates.appendingPathComponent(digest, isDirectory: true)
    }

    func environmentDirectory(_ environment: String) throws -> URL {
        try validateIdentifier(environment)
        return environments.appendingPathComponent(environment, isDirectory: true)
    }

    func loadTemplate(image: String, verifyArtifacts: Bool = true) throws -> (TemplateManifest, URL) {
        let parsed = try parsePinnedImage(image)
        let directory = templateDirectory(parsed.digest)
        let manifestURL = directory.appendingPathComponent(Self.manifestName)
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw HelperFailure(exit: .missing, message: "template is not installed")
        }
        let manifest: TemplateManifest = try decodeFile(manifestURL, failure: "template inventory is invalid")
        try manifest.validateIdentity()
        guard manifest.templateDigest == parsed.digest,
              manifest.identity.version == parsed.version,
              manifest.image == image,
              manifest.identity.schemaVersion == 1,
              manifest.identity.guestOs == "macos",
              manifest.identity.architecture == hostArchitecture(),
              manifest.identity.bootstrapProtocol == protocolVersion,
              manifest.identity.processLimit == requiredProcessLimit,
              manifest.identity.processLimitMechanism == "rlimit_nproc_dedicated_uid",
              manifest.immutable,
              manifest.bootstrapReady
        else {
            throw HelperFailure.rejected("template is incompatible")
        }
        if verifyArtifacts {
            let artifacts = [
                (Self.diskName, manifest.identity.diskSha256),
                (Self.auxiliaryName, manifest.identity.auxiliaryStorageSha256),
                (Self.hardwareModelName, manifest.identity.hardwareModelSha256),
            ]
            for (name, expected) in artifacts {
                let url = directory.appendingPathComponent(name)
                guard isRegularFile(url), try sha256(url: url) == expected else {
                    throw HelperFailure.rejected("template artifact identity mismatch")
                }
            }
        }
        return (manifest, directory)
    }

    func registerTemplate(
        version: String,
        architecture: String,
        diskMiB: UInt32,
        bootstrapPort: UInt32,
        disk: URL,
        auxiliaryStorage: URL,
        hardwareModel: URL
    ) throws -> TemplateManifest {
        guard architecture == hostArchitecture(), architecture == "arm64",
              diskMiB > 0,
              bootstrapPort >= 1024,
              isRegularFile(disk),
              isRegularFile(auxiliaryStorage),
              isRegularFile(hardwareModel),
              logicalSize(disk) == UInt64(diskMiB) * 1024 * 1024
        else {
            throw HelperFailure.rejected("template artifacts are incompatible")
        }
        try validateTemplateHardwareModel(hardwareModel)
        let identity = TemplateIdentity(
            schemaVersion: 1,
            version: version,
            guestOs: "macos",
            architecture: architecture,
            diskMib: diskMiB,
            diskSha256: try sha256(url: disk),
            auxiliaryStorageSha256: try sha256(url: auxiliaryStorage),
            hardwareModelSha256: try sha256(url: hardwareModel),
            bootstrapProtocol: protocolVersion,
            bootstrapPort: bootstrapPort,
            processLimit: UInt32(requiredProcessLimit),
            processLimitMechanism: "rlimit_nproc_dedicated_uid"
        )
        let manifest = try TemplateManifest.make(identity: identity)
        _ = try parsePinnedImage(manifest.image)
        let destination = templateDirectory(manifest.templateDigest)
        if FileManager.default.fileExists(atPath: destination.path) {
            let (existing, _) = try loadTemplate(image: manifest.image)
            guard existing == manifest else {
                throw HelperFailure.rejected("template digest collision")
            }
            return existing
        }

        let staging = templates.appendingPathComponent(".register-\(UUID().uuidString)", isDirectory: true)
        try ensureDirectory(staging)
        do {
            try copyFile(disk, staging.appendingPathComponent(Self.diskName))
            try copyFile(auxiliaryStorage, staging.appendingPathComponent(Self.auxiliaryName))
            try copyFile(hardwareModel, staging.appendingPathComponent(Self.hardwareModelName))
            try writeFile(manifest, to: staging.appendingPathComponent(Self.manifestName))
            for name in [Self.diskName, Self.auxiliaryName, Self.hardwareModelName, Self.manifestName] {
                try setPermissions(staging.appendingPathComponent(name), mode: 0o400)
            }
            try setPermissions(staging, mode: 0o500)
            try FileManager.default.moveItem(at: staging, to: destination)
        } catch {
            try? FileManager.default.removeItem(at: staging)
            throw sanitized(error, "template registration failed")
        }
        return manifest
    }

    func prepare(
        environment: String,
        host: String,
        attempt: String,
        generation: String,
        image: String,
        templateDigest: String,
        architecture: String,
        cpuMillis: UInt32,
        memoryMiB: UInt32,
        diskMiB: UInt32,
        processLimit: UInt32,
        runnerSource: URL
    ) throws {
        let destination = try environmentDirectory(environment)
        guard !FileManager.default.fileExists(atPath: destination.path),
              UUID(uuidString: host) != nil,
              UUID(uuidString: attempt) != nil,
              !generation.isEmpty,
              generation.count <= 256,
              templateDigest == (try parsePinnedImage(image)).digest,
              architecture == hostArchitecture(), architecture == "arm64",
              cpuMillis > 0, cpuMillis % 1000 == 0,
              memoryMiB > 0,
              diskMiB > 0,
              processLimit == requiredProcessLimit,
              isDirectory(runnerSource)
        else {
            throw HelperFailure.rejected("prepare request is invalid")
        }
        let (manifest, template) = try loadTemplate(image: image)
        guard manifest.templateDigest == templateDigest,
              manifest.identity.diskMib == diskMiB,
              logicalSize(template.appendingPathComponent(Self.diskName)) == UInt64(diskMiB) * 1024 * 1024
        else {
            throw HelperFailure.rejected("requested disk limit does not match the pinned template")
        }
        try validateResourceConfiguration(cpuMillis: cpuMillis, memoryMiB: memoryMiB)

        let staging = environments.appendingPathComponent(".prepare-\(UUID().uuidString)", isDirectory: true)
        try ensureDirectory(staging)
        do {
            try cloneFile(
                template.appendingPathComponent(Self.diskName),
                staging.appendingPathComponent(Self.diskName)
            )
            try cloneFile(
                template.appendingPathComponent(Self.auxiliaryName),
                staging.appendingPathComponent(Self.auxiliaryName)
            )
            try copyFile(
                template.appendingPathComponent(Self.hardwareModelName),
                staging.appendingPathComponent(Self.hardwareModelName)
            )
            try createMachineIdentifier(at: staging.appendingPathComponent(Self.machineIdentifierName))
            try archiveRunner(source: runnerSource, destination: staging.appendingPathComponent(Self.runnerArchiveName))
            try setPermissions(staging.appendingPathComponent(Self.diskName), mode: 0o600)
            try setPermissions(staging.appendingPathComponent(Self.auxiliaryName), mode: 0o600)
            try setPermissions(staging.appendingPathComponent(Self.hardwareModelName), mode: 0o600)

            let record = EnvironmentRecord(
                protocolVersion: protocolVersion,
                environmentId: environment,
                state: .prepared,
                hostId: host,
                attemptId: attempt,
                generation: generation,
                image: image,
                templateDigest: templateDigest,
                guestOs: "macos",
                architecture: architecture,
                writableDiskId: UUID().uuidString.lowercased(),
                freshWritableDisk: true,
                sharedHostPaths: [],
                jitChannel: "private",
                appliedCpuMillis: cpuMillis,
                appliedMemoryMib: memoryMiB,
                appliedDiskMib: diskMiB,
                appliedProcessLimit: processLimit,
                runnerExitCode: nil,
                supervisorPid: nil,
                supervisorToken: UUID().uuidString.lowercased()
            )
            try writeRecord(record, directory: staging)
            try FileManager.default.moveItem(at: staging, to: destination)
        } catch {
            try? FileManager.default.removeItem(at: staging)
            throw sanitized(error, "environment preparation failed")
        }
    }

    func loadRecord(_ environment: String, reconcile: Bool = true) throws -> EnvironmentRecord {
        let directory = try environmentDirectory(environment)
        let url = directory.appendingPathComponent(Self.metadataName)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw HelperFailure(exit: .missing, message: "environment is absent")
        }
        var record: EnvironmentRecord = try decodeFile(url, failure: "environment metadata is invalid")
        guard record.protocolVersion == protocolVersion,
              record.environmentId == environment,
              record.guestOs == "macos",
              record.architecture == hostArchitecture(),
              record.freshWritableDisk,
              record.sharedHostPaths.isEmpty,
              record.jitChannel == "private",
              record.appliedProcessLimit == requiredProcessLimit
        else {
            throw HelperFailure.rejected("environment metadata is incompatible")
        }
        if reconcile,
           (record.state == .booting || record.state == .running),
           !supervisorMatches(record)
        {
            record.state = .stopped
            record.supervisorPid = nil
            try writeRecord(record, directory: directory)
        }
        return record
    }

    func writeRecord(_ record: EnvironmentRecord) throws {
        try writeRecord(record, directory: try environmentDirectory(record.environmentId))
    }

    private func writeRecord(_ record: EnvironmentRecord, directory: URL) throws {
        try writeFile(record, to: directory.appendingPathComponent(Self.metadataName))
    }

    func list(host: String) throws -> [EnvironmentRecord] {
        guard UUID(uuidString: host) != nil else { throw HelperFailure.rejected("host identity is invalid") }
        let directories = try FileManager.default.contentsOfDirectory(
            at: environments,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        )
        return directories.compactMap { directory in
            guard let record = try? loadRecord(directory.lastPathComponent), record.hostId == host else { return nil }
            return record
        }.sorted { $0.environmentId < $1.environmentId }
    }

    func destroy(_ record: EnvironmentRecord) throws {
        guard record.state != .booting, record.state != .running, !supervisorMatches(record) else {
            throw HelperFailure.degraded("environment is still running")
        }
        try FileManager.default.removeItem(at: try environmentDirectory(record.environmentId))
    }
}

func ensureDirectory(_ url: URL) throws {
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    try setPermissions(url, mode: 0o700)
}

func setPermissions(_ url: URL, mode: Int16) throws {
    try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: url.path)
}

func isRegularFile(_ url: URL) -> Bool {
    (try? url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
}

func isDirectory(_ url: URL) -> Bool {
    (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
}

func logicalSize(_ url: URL) -> UInt64? {
    guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
          let value = attributes[.size] as? NSNumber
    else {
        return nil
    }
    return value.uint64Value
}

func decodeFile<T: Decodable>(_ url: URL, failure: String) throws -> T {
    do {
        return try protocolDecoder.decode(T.self, from: Data(contentsOf: url, options: [.mappedIfSafe]))
    } catch {
        throw HelperFailure.degraded(failure)
    }
}

func writeFile<T: Encodable>(_ value: T, to url: URL) throws {
    do {
        try protocolEncoder.encode(value).write(to: url, options: [.atomic])
        try setPermissions(url, mode: 0o600)
    } catch {
        throw HelperFailure.degraded("durable metadata write failed")
    }
}

func copyFile(_ source: URL, _ destination: URL) throws {
    guard !FileManager.default.fileExists(atPath: destination.path) else {
        throw HelperFailure.degraded("artifact destination already exists")
    }
    try FileManager.default.copyItem(at: source, to: destination)
}

func cloneFile(_ source: URL, _ destination: URL) throws {
    let result = source.path.withCString { sourcePath in
        destination.path.withCString { destinationPath in
            clonefile(sourcePath, destinationPath, 0)
        }
    }
    guard result == 0 else {
        throw HelperFailure.degraded("fresh APFS writable clone is unavailable")
    }
}

func archiveRunner(source: URL, destination: URL) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
    process.arguments = ["-C", source.path, "-cf", destination.path, "."]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    let done = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in done.signal() }
    do { try process.run() } catch { throw HelperFailure.degraded("runner archive creation failed") }
    if done.wait(timeout: .now() + operationTimeout) == .timedOut {
        process.terminate()
        throw HelperFailure.degraded("runner archive creation timed out")
    }
    guard process.terminationStatus == 0, isRegularFile(destination) else {
        throw HelperFailure.degraded("runner archive creation failed")
    }
    try setPermissions(destination, mode: 0o600)
}

func sanitized(_ error: Error, _ fallback: String) -> HelperFailure {
    if let failure = error as? HelperFailure { return failure }
    if isPermissionDenied(error) {
        return HelperFailure(exit: .permission, message: "helper store permission denied")
    }
    return HelperFailure.degraded(fallback)
}

private func isPermissionDenied(_ error: Error) -> Bool {
    let cocoa = error as NSError
    if cocoa.domain == NSPOSIXErrorDomain,
       cocoa.code == Int(EACCES) || cocoa.code == Int(EPERM)
    {
        return true
    }
    if cocoa.domain == NSCocoaErrorDomain,
       cocoa.code == NSFileReadNoPermissionError || cocoa.code == NSFileWriteNoPermissionError
    {
        return true
    }
    if let underlying = cocoa.userInfo[NSUnderlyingErrorKey] as? Error {
        return isPermissionDenied(underlying)
    }
    return false
}
