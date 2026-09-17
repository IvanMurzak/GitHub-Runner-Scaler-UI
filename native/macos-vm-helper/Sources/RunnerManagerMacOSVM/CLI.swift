import Darwin
import Foundation

@main
struct RunnerManagerMacOSVM {
    static func main() {
        do {
            var arguments = Array(CommandLine.arguments.dropFirst())
            if arguments.first == "--internal-supervise" {
                try runInternalSupervisor(arguments)
            } else {
                try runProtocol(&arguments)
            }
        } catch let failure as HelperFailure {
            writeError(failure.message)
            Darwin.exit(failure.exit.rawValue)
        } catch {
            writeError("helper operation failed")
            Darwin.exit(Exit.failure.rawValue)
        }
    }

    private static func runProtocol(_ arguments: inout [String]) throws {
        guard arguments.count >= 3,
              arguments.removeFirst() == "--protocol-version",
              arguments.removeFirst() == String(protocolVersion)
        else {
            throw HelperFailure.rejected("unsupported protocol version")
        }
        let store = try Store()
        let command = arguments.removeFirst()
        switch command {
        case "probe":
            try expectOnly(arguments, ["--json"])
            let entitlement = hasVirtualizationEntitlement()
            let framework = virtualizationIsReady()
            // APFS clone readiness is an independent host prerequisite. Probe
            // it even when Virtualization.framework is unavailable so the
            // response identifies the actual blocked layer instead of hiding
            // a usable filesystem behind a runtime failure.
            let clones = supportsFreshClones(in: store.root)
            try writeJSON(ProbeResponse(
                protocolVersion: protocolVersion,
                architecture: hostArchitecture(),
                virtualizationFramework: framework,
                macosGuestEntitlement: entitlement,
                privateJitChannel: framework && entitlement,
                freshWritableDisks: clones,
                resourceLimits: framework && entitlement,
                processLimits: framework && entitlement
            ))
        case "image":
            guard arguments.first == "inspect" else { throw HelperFailure.rejected("unsupported image command") }
            arguments.removeFirst()
            let options = try Options(arguments, values: ["--image"], flags: ["--json"])
            let image = try options.required("--image")
            let (manifest, _) = try store.loadTemplate(image: image)
            try writeJSON(ImageResponse(
                protocolVersion: protocolVersion,
                image: manifest.image,
                templateDigest: manifest.templateDigest,
                guestOs: manifest.identity.guestOs,
                architecture: manifest.identity.architecture,
                immutable: manifest.immutable,
                bootstrapReady: manifest.bootstrapReady
            ))
        case "template":
            try registerTemplate(store: store, arguments: arguments)
        case "prepare":
            try prepare(store: store, arguments: arguments)
        case "inspect":
            let options = try Options(arguments, values: ["--environment"], flags: ["--json"])
            let record = try store.loadRecord(try options.required("--environment"))
            try writeJSON(record.publicRecord())
        case "list":
            let options = try Options(arguments, values: ["--host"], flags: ["--json"])
            try writeJSON(try store.list(host: options.required("--host")).map { $0.publicRecord() })
        case "start":
            let options = try Options(arguments, values: ["--environment"], flags: ["--jit-stdin"])
            let record = try store.loadRecord(options.required("--environment"))
            var jit = try readBoundedStandardInput()
            defer { jit.resetBytes(in: 0..<jit.count) }
            try launchSupervisor(store: store, record: record, jit: &jit)
        case "stop":
            let (record, _) = try ownedRecord(store: store, arguments: arguments)
            try stopEnvironment(store: store, record: record)
        case "destroy":
            var (record, _) = try ownedRecord(store: store, arguments: arguments)
            if supervisorMatches(record) || record.state == .running || record.state == .booting {
                try stopEnvironment(store: store, record: record)
                record = try store.loadRecord(record.environmentId)
            }
            try store.destroy(record)
        default:
            throw HelperFailure.rejected("unsupported helper command")
        }
    }

    private static func prepare(store: Store, arguments: [String]) throws {
        let values: Set<String> = [
            "--environment", "--host", "--attempt", "--generation", "--image",
            "--template-digest", "--architecture", "--cpu-millis", "--memory-mib",
            "--disk-mib", "--process-limit", "--runner-source",
        ]
        let flags: Set<String> = ["--fresh-writable-disk", "--no-host-shares", "--private-jit-channel"]
        let options = try Options(arguments, values: values, flags: flags)
        guard options.has("--fresh-writable-disk"),
              options.has("--no-host-shares"),
              options.has("--private-jit-channel")
        else {
            throw HelperFailure.rejected("required isolation control is absent")
        }
        try store.prepare(
            environment: options.required("--environment"),
            host: options.required("--host"),
            attempt: options.required("--attempt"),
            generation: options.required("--generation"),
            image: options.required("--image"),
            templateDigest: options.required("--template-digest"),
            architecture: options.required("--architecture"),
            cpuMillis: options.uint32("--cpu-millis"),
            memoryMiB: options.uint32("--memory-mib"),
            diskMiB: options.uint32("--disk-mib"),
            processLimit: options.uint32("--process-limit"),
            runnerSource: URL(fileURLWithPath: options.required("--runner-source"), isDirectory: true)
        )
    }

    private static func registerTemplate(store: Store, arguments: [String]) throws {
        guard arguments.first == "register" else { throw HelperFailure.rejected("unsupported template command") }
        let options = try Options(
            Array(arguments.dropFirst()),
            values: [
                "--version", "--architecture", "--disk-mib", "--bootstrap-port",
                "--disk", "--auxiliary-storage", "--hardware-model",
            ],
            flags: []
        )
        let manifest = try store.registerTemplate(
            version: options.required("--version"),
            architecture: options.required("--architecture"),
            diskMiB: options.uint32("--disk-mib"),
            bootstrapPort: options.uint32("--bootstrap-port"),
            disk: absoluteURL(options.required("--disk")),
            auxiliaryStorage: absoluteURL(options.required("--auxiliary-storage")),
            hardwareModel: absoluteURL(options.required("--hardware-model"))
        )
        try writeJSON(manifest)
    }

    private static func ownedRecord(store: Store, arguments: [String]) throws -> (EnvironmentRecord, Options) {
        let options = try Options(
            arguments,
            values: ["--environment", "--host", "--attempt", "--generation"],
            flags: []
        )
        let record = try store.loadRecord(options.required("--environment"))
        let host = try options.required("--host")
        let attempt = try options.required("--attempt")
        let generation = try options.required("--generation")
        guard record.hostId == host,
              record.attemptId == attempt,
              record.generation == generation
        else {
            throw HelperFailure.rejected("environment ownership mismatch")
        }
        return (record, options)
    }

    private static func runInternalSupervisor(_ arguments: [String]) throws -> Never {
        guard arguments.count == 3 else { throw HelperFailure.rejected("invalid supervisor invocation") }
        let environment = arguments[1]
        let token = arguments[2]
        let store = try Store()
        let record = try store.loadRecord(environment, reconcile: false)
        guard record.supervisorToken == token else { throw HelperFailure.rejected("supervisor ownership mismatch") }
        var jit = try readBoundedStandardInput()
        defer { jit.resetBytes(in: 0..<jit.count) }
        do {
            return try Supervisor(store: store, record: record).run(jit: &jit)
        } catch {
            var failed = record
            failed.state = .stopped
            failed.supervisorPid = nil
            try? store.writeRecord(failed)
            try? FileHandle.standardOutput.write(contentsOf: Data("ERROR\n".utf8))
            try? FileHandle.standardOutput.close()
            throw error
        }
    }
}

struct Options {
    private let values: [String: String]
    private let flags: Set<String>

    init(_ arguments: [String], values allowedValues: Set<String>, flags allowedFlags: Set<String>) throws {
        var parsedValues: [String: String] = [:]
        var parsedFlags: Set<String> = []
        var index = 0
        while index < arguments.count {
            let option = arguments[index]
            if allowedFlags.contains(option) {
                guard parsedFlags.insert(option).inserted else { throw HelperFailure.rejected("duplicate option") }
                index += 1
            } else if allowedValues.contains(option) {
                guard parsedValues[option] == nil, index + 1 < arguments.count else {
                    throw HelperFailure.rejected("invalid option value")
                }
                parsedValues[option] = arguments[index + 1]
                index += 2
            } else {
                throw HelperFailure.rejected("unknown option")
            }
        }
        self.values = parsedValues
        flags = parsedFlags
    }

    func required(_ name: String) throws -> String {
        guard let value = values[name], !value.isEmpty else { throw HelperFailure.rejected("required option is absent") }
        return value
    }

    func uint32(_ name: String) throws -> UInt32 {
        guard let value = UInt32(try required(name)) else { throw HelperFailure.rejected("numeric option is invalid") }
        return value
    }

    func has(_ name: String) -> Bool { flags.contains(name) }
}

func absoluteURL(_ path: String) -> URL {
    URL(fileURLWithPath: path).standardizedFileURL
}

func expectOnly(_ arguments: [String], _ expected: [String]) throws {
    guard arguments == expected else { throw HelperFailure.rejected("invalid command options") }
}

func readBoundedStandardInput() throws -> Data {
    var result = Data()
    while true {
        let part = try FileHandle.standardInput.read(upToCount: 64 * 1024) ?? Data()
        if part.isEmpty { break }
        guard result.count + part.count <= maximumJITBytes else {
            result.resetBytes(in: 0..<result.count)
            throw HelperFailure.rejected("JIT document exceeds its bound")
        }
        result.append(part)
    }
    guard !result.isEmpty else { throw HelperFailure.rejected("JIT document is absent") }
    return result
}

func writeJSON<T: Encodable>(_ value: T) throws {
    var data = try protocolEncoder.encode(value)
    data.append(0x0A)
    guard data.count <= 64 * 1024 else { throw HelperFailure.degraded("protocol response exceeds its bound") }
    try FileHandle.standardOutput.write(contentsOf: data)
}

func writeError(_ message: String) {
    let redacted = message.replacingOccurrences(of: "\n", with: " ").prefix(512)
    try? FileHandle.standardError.write(contentsOf: Data("runner-manager-macos-vm: \(redacted)\n".utf8))
}

func supportsFreshClones(in root: URL) -> Bool {
    let source = root.appendingPathComponent(".clone-probe-\(UUID().uuidString)")
    let destination = root.appendingPathComponent(".clone-probe-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: source)
        try? FileManager.default.removeItem(at: destination)
    }
    do {
        try Data([0]).write(to: source, options: [.withoutOverwriting])
        try cloneFile(source, destination)
        return true
    } catch {
        return false
    }
}
