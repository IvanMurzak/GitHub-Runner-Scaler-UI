import CryptoKit
import Foundation

let protocolVersion = 1
let requiredProcessLimit = 512
let maximumJITBytes = 1024 * 1024
let maximumGuestReplyBytes = 64 * 1024
let operationTimeout: TimeInterval = 240

enum Exit: Int32 {
    case failure = 1
    case missing = 66
    case permission = 77
    case unsupported = 78
}

struct HelperFailure: Error {
    let exit: Exit
    let message: String

    static func rejected(_ message: String) -> Self {
        Self(exit: .unsupported, message: message)
    }

    static func degraded(_ message: String) -> Self {
        Self(exit: .failure, message: message)
    }
}

struct ProbeResponse: Codable, Equatable {
    let protocolVersion: Int
    let architecture: String
    let virtualizationFramework: Bool
    let macosGuestEntitlement: Bool
    let privateJitChannel: Bool
    let freshWritableDisks: Bool
    let resourceLimits: Bool
    let processLimits: Bool
}

struct ImageResponse: Codable, Equatable {
    let protocolVersion: Int
    let image: String
    let templateDigest: String
    let guestOs: String
    let architecture: String
    let immutable: Bool
    let bootstrapReady: Bool
}

enum EnvironmentState: String, Codable {
    case prepared
    case booting
    case running
    case exited
    case stopped
}

struct EnvironmentRecord: Codable, Equatable {
    let protocolVersion: Int
    let environmentId: String
    var state: EnvironmentState
    let hostId: String
    let attemptId: String
    let generation: String
    let image: String
    let templateDigest: String
    let guestOs: String
    let architecture: String
    let writableDiskId: String
    let freshWritableDisk: Bool
    let sharedHostPaths: [String]
    let jitChannel: String
    let appliedCpuMillis: UInt32
    let appliedMemoryMib: UInt32
    let appliedDiskMib: UInt32
    let appliedProcessLimit: UInt32
    var runnerExitCode: Int32?

    // Private recovery fields are intentionally excluded from protocol JSON.
    var supervisorPid: Int32?
    let supervisorToken: String

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case environmentId = "environment_id"
        case state
        case hostId = "host_id"
        case attemptId = "attempt_id"
        case generation
        case image
        case templateDigest = "template_digest"
        case guestOs = "guest_os"
        case architecture
        case writableDiskId = "writable_disk_id"
        case freshWritableDisk = "fresh_writable_disk"
        case sharedHostPaths = "shared_host_paths"
        case jitChannel = "jit_channel"
        case appliedCpuMillis = "applied_cpu_millis"
        case appliedMemoryMib = "applied_memory_mib"
        case appliedDiskMib = "applied_disk_mib"
        case appliedProcessLimit = "applied_process_limit"
        case runnerExitCode = "runner_exit_code"
        case supervisorPid = "_supervisor_pid"
        case supervisorToken = "_supervisor_token"
    }

    func publicRecord() -> PublicEnvironmentRecord {
        PublicEnvironmentRecord(record: self)
    }
}

struct PublicEnvironmentRecord: Codable, Equatable {
    let protocolVersion: Int
    let environmentId: String
    let state: EnvironmentState
    let hostId: String
    let attemptId: String
    let generation: String
    let image: String
    let templateDigest: String
    let guestOs: String
    let architecture: String
    let writableDiskId: String
    let freshWritableDisk: Bool
    let sharedHostPaths: [String]
    let jitChannel: String
    let appliedCpuMillis: UInt32
    let appliedMemoryMib: UInt32
    let appliedDiskMib: UInt32
    let appliedProcessLimit: UInt32
    let runnerExitCode: Int32?

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case environmentId = "environment_id"
        case state
        case hostId = "host_id"
        case attemptId = "attempt_id"
        case generation
        case image
        case templateDigest = "template_digest"
        case guestOs = "guest_os"
        case architecture
        case writableDiskId = "writable_disk_id"
        case freshWritableDisk = "fresh_writable_disk"
        case sharedHostPaths = "shared_host_paths"
        case jitChannel = "jit_channel"
        case appliedCpuMillis = "applied_cpu_millis"
        case appliedMemoryMib = "applied_memory_mib"
        case appliedDiskMib = "applied_disk_mib"
        case appliedProcessLimit = "applied_process_limit"
        case runnerExitCode = "runner_exit_code"
    }

    init(record: EnvironmentRecord) {
        protocolVersion = record.protocolVersion
        environmentId = record.environmentId
        state = record.state
        hostId = record.hostId
        attemptId = record.attemptId
        generation = record.generation
        image = record.image
        templateDigest = record.templateDigest
        guestOs = record.guestOs
        architecture = record.architecture
        writableDiskId = record.writableDiskId
        freshWritableDisk = record.freshWritableDisk
        sharedHostPaths = record.sharedHostPaths
        jitChannel = record.jitChannel
        appliedCpuMillis = record.appliedCpuMillis
        appliedMemoryMib = record.appliedMemoryMib
        appliedDiskMib = record.appliedDiskMib
        appliedProcessLimit = record.appliedProcessLimit
        runnerExitCode = record.runnerExitCode
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(protocolVersion, forKey: .protocolVersion)
        try values.encode(environmentId, forKey: .environmentId)
        try values.encode(state, forKey: .state)
        try values.encode(hostId, forKey: .hostId)
        try values.encode(attemptId, forKey: .attemptId)
        try values.encode(generation, forKey: .generation)
        try values.encode(image, forKey: .image)
        try values.encode(templateDigest, forKey: .templateDigest)
        try values.encode(guestOs, forKey: .guestOs)
        try values.encode(architecture, forKey: .architecture)
        try values.encode(writableDiskId, forKey: .writableDiskId)
        try values.encode(freshWritableDisk, forKey: .freshWritableDisk)
        try values.encode(sharedHostPaths, forKey: .sharedHostPaths)
        try values.encode(jitChannel, forKey: .jitChannel)
        try values.encode(appliedCpuMillis, forKey: .appliedCpuMillis)
        try values.encode(appliedMemoryMib, forKey: .appliedMemoryMib)
        try values.encode(appliedDiskMib, forKey: .appliedDiskMib)
        try values.encode(appliedProcessLimit, forKey: .appliedProcessLimit)
        if let runnerExitCode {
            try values.encode(runnerExitCode, forKey: .runnerExitCode)
        } else {
            try values.encodeNil(forKey: .runnerExitCode)
        }
    }
}

struct TemplateIdentity: Codable, Equatable {
    let schemaVersion: Int
    let version: String
    let guestOs: String
    let architecture: String
    let diskMib: UInt32
    let diskSha256: String
    let auxiliaryStorageSha256: String
    let hardwareModelSha256: String
    let bootstrapProtocol: Int
    let bootstrapPort: UInt32
    let processLimit: UInt32
    let processLimitMechanism: String

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case version
        case guestOs = "guest_os"
        case architecture
        case diskMib = "disk_mib"
        case diskSha256 = "disk_sha256"
        case auxiliaryStorageSha256 = "auxiliary_storage_sha256"
        case hardwareModelSha256 = "hardware_model_sha256"
        case bootstrapProtocol = "bootstrap_protocol"
        case bootstrapPort = "bootstrap_port"
        case processLimit = "process_limit"
        case processLimitMechanism = "process_limit_mechanism"
    }
}

struct TemplateManifest: Codable, Equatable {
    let identity: TemplateIdentity
    let templateDigest: String
    let image: String
    let immutable: Bool
    let bootstrapReady: Bool

    enum CodingKeys: String, CodingKey {
        case identity
        case templateDigest = "template_digest"
        case image
        case immutable
        case bootstrapReady = "bootstrap_ready"
    }

    static func make(identity: TemplateIdentity) throws -> Self {
        let digest = try digestIdentity(identity)
        return Self(
            identity: identity,
            templateDigest: digest,
            image: "vm-version:\(identity.version)@sha256:\(digest)",
            immutable: true,
            bootstrapReady: true
        )
    }

    func validateIdentity() throws {
        guard templateDigest == (try Self.digestIdentity(identity)),
              image == "vm-version:\(identity.version)@sha256:\(templateDigest)"
        else {
            throw HelperFailure.rejected("template identity mismatch")
        }
    }

    private static func digestIdentity(_ identity: TemplateIdentity) throws -> String {
        var material = Data("runner-manager-macos-vm-template-v1\n".utf8)
        material.append(try protocolEncoder.encode(identity))
        return SHA256.hash(data: material).hex
    }
}

struct GuestStartHeader: Codable {
    let protocolVersion: Int
    let command: String
    let environmentId: String
    let generation: String
    let runnerArchiveBytes: UInt64
    let runnerArchiveSha256: String
    let jitBytes: UInt64
    let processLimit: UInt32
    let processLimitMechanism: String

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case command
        case environmentId = "environment_id"
        case generation
        case runnerArchiveBytes = "runner_archive_bytes"
        case runnerArchiveSha256 = "runner_archive_sha256"
        case jitBytes = "jit_bytes"
        case processLimit = "process_limit"
        case processLimitMechanism = "process_limit_mechanism"
    }
}

struct GuestReply: Codable {
    let protocolVersion: Int
    let status: String
    let environmentId: String
    let generation: String
    let appliedProcessLimit: UInt32?
    let processLimitMechanism: String?
    let runnerUidExclusive: Bool?
    let runnerPid: Int32?
    let runnerExitCode: Int32?

    enum CodingKeys: String, CodingKey {
        case protocolVersion = "protocol_version"
        case status
        case environmentId = "environment_id"
        case generation
        case appliedProcessLimit = "applied_process_limit"
        case processLimitMechanism = "process_limit_mechanism"
        case runnerUidExclusive = "runner_uid_exclusive"
        case runnerPid = "runner_pid"
        case runnerExitCode = "runner_exit_code"
    }
}

let protocolEncoder: JSONEncoder = {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return encoder
}()

let protocolDecoder = JSONDecoder()

extension Digest {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

func sha256(url: URL) throws -> String {
    guard let stream = InputStream(url: url) else {
        throw HelperFailure.degraded("artifact cannot be read")
    }
    stream.open()
    defer { stream.close() }
    var hasher = SHA256()
    var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
    while stream.hasBytesAvailable {
        let count = stream.read(&buffer, maxLength: buffer.count)
        if count < 0 { throw HelperFailure.degraded("artifact cannot be read") }
        if count == 0 { break }
        hasher.update(data: Data(buffer[0..<count]))
    }
    return hasher.finalize().hex
}

func hostArchitecture() -> String {
#if arch(arm64)
    return "arm64"
#elseif arch(x86_64)
    return "x86_64"
#else
    return "unsupported"
#endif
}

func parsePinnedImage(_ image: String) throws -> (version: String, digest: String) {
    let prefix = "vm-version:"
    let separator = "@sha256:"
    guard image.hasPrefix(prefix), let range = image.range(of: separator) else {
        throw HelperFailure.rejected("image must be versioned and digest pinned")
    }
    let version = String(image[image.index(image.startIndex, offsetBy: prefix.count)..<range.lowerBound])
    let digest = String(image[range.upperBound...])
    let allowedVersion = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    guard !version.isEmpty,
          version.unicodeScalars.allSatisfy(allowedVersion.contains),
          digest.count == 64,
          digest.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) })
    else {
        throw HelperFailure.rejected("image must be versioned and digest pinned")
    }
    return (version, digest)
}

func validateIdentifier(_ value: String) throws {
    let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    guard value.hasPrefix("rm-"),
          !value.contains(".."),
          value.count <= 192,
          value.unicodeScalars.allSatisfy(allowed.contains)
    else {
        throw HelperFailure.rejected("invalid environment identity")
    }
}
