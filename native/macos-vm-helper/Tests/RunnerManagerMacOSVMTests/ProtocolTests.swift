import CryptoKit
import Foundation
import XCTest
@testable import RunnerManagerMacOSVM

final class ProtocolTests: XCTestCase {
    func testStorePermissionErrorsRemainTypedAndRedacted() {
        let underlying = NSError(domain: NSPOSIXErrorDomain, code: Int(EACCES), userInfo: [
            NSLocalizedDescriptionKey: "token=secret path=/private/guest-output",
        ])
        let denied = sanitized(
            NSError(domain: NSCocoaErrorDomain, code: 999, userInfo: [
                NSUnderlyingErrorKey: underlying,
                NSLocalizedDescriptionKey: "credential=secret",
            ]),
            "helper store initialization failed"
        )
        XCTAssertEqual(denied.exit, .permission)
        XCTAssertEqual(denied.message, "helper store permission denied")

        let other = sanitized(
            NSError(domain: NSCocoaErrorDomain, code: 1, userInfo: [
                NSLocalizedDescriptionKey: "credential=secret",
            ]),
            "helper store initialization failed"
        )
        XCTAssertEqual(other.exit, .failure)
        XCTAssertEqual(other.message, "helper store initialization failed")
    }

    func testSupervisorReceivesOnlyThePrivateStoreLocation() {
        let root = URL(fileURLWithPath: "/private/runner-manager-vm-store", isDirectory: true)
        XCTAssertEqual(
            supervisorEnvironment(storeRoot: root),
            ["RUNNER_MANAGER_MACOS_VM_ROOT": root.path]
        )
    }

    func testProbeResponseUsesTheDocumentedWireKeys() throws {
        let response = ProbeResponse(
            protocolVersion: 1,
            architecture: "arm64",
            virtualizationFramework: false,
            macosGuestEntitlement: true,
            privateJitChannel: false,
            freshWritableDisks: true,
            resourceLimits: false,
            processLimits: false
        )
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: protocolEncoder.encode(response)) as? [String: Any]
        )
        XCTAssertEqual(Set(json.keys), Set([
            "protocol_version",
            "architecture",
            "virtualization_framework",
            "macos_guest_entitlement",
            "private_jit_channel",
            "fresh_writable_disks",
            "resource_limits",
            "process_limits",
        ]))
    }

    func testPinnedImageParserRejectsMutableAndNonCanonicalReferences() throws {
        let digest = String(repeating: "a", count: 64)
        XCTAssertEqual(try parsePinnedImage("vm-version:macos-15-arm64-v1@sha256:\(digest)").digest, digest)
        for invalid in [
            "latest",
            "vm-version:latest",
            "vm-version:v1@sha256:ABC",
            "vm-version:../v1@sha256:\(digest)",
            "vm-version:v1@sha256:\(String(repeating: "g", count: 64))",
            "vm-version:v1@sha256:\(String(repeating: "١", count: 64))",
        ] {
            XCTAssertThrowsError(try parsePinnedImage(invalid), invalid)
        }
    }

    func testEnvironmentIdentifiersCannotEscapeOrHideFromInventory() throws {
        XCTAssertNoThrow(try validateIdentifier("rm-attempt-generation"))
        for invalid in ["..", ".hidden", "rm-..", "other-environment", "rm-path/slash"] {
            XCTAssertThrowsError(try validateIdentifier(invalid), invalid)
        }
    }

    func testTemplateDigestCoversBootstrapAndEveryArtifactDigest() throws {
        let base = TemplateIdentity(
            schemaVersion: 1,
            version: "macos-15-arm64-v1",
            guestOs: "macos",
            architecture: "arm64",
            diskMib: 32_768,
            diskSha256: String(repeating: "a", count: 64),
            auxiliaryStorageSha256: String(repeating: "b", count: 64),
            hardwareModelSha256: String(repeating: "c", count: 64),
            bootstrapProtocol: 1,
            bootstrapPort: 22022,
            processLimit: 512,
            processLimitMechanism: "rlimit_nproc_dedicated_uid"
        )
        let first = try TemplateManifest.make(identity: base)
        XCTAssertEqual(first, try TemplateManifest.make(identity: base))
        try first.validateIdentity()

        let changed = TemplateIdentity(
            schemaVersion: base.schemaVersion,
            version: base.version,
            guestOs: base.guestOs,
            architecture: base.architecture,
            diskMib: base.diskMib,
            diskSha256: base.diskSha256,
            auxiliaryStorageSha256: base.auxiliaryStorageSha256,
            hardwareModelSha256: base.hardwareModelSha256,
            bootstrapProtocol: base.bootstrapProtocol,
            bootstrapPort: base.bootstrapPort + 1,
            processLimit: base.processLimit,
            processLimitMechanism: base.processLimitMechanism
        )
        XCTAssertNotEqual(first.templateDigest, try TemplateManifest.make(identity: changed).templateDigest)
    }

    func testHotTemplateLoadUsesPinnedInventoryAndExplicitVerificationChecksBytes() throws {
        let temporary = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: temporary) }
        let store = try Store(environment: ["RUNNER_MANAGER_MACOS_VM_ROOT": temporary.path])
        let disk = Data("registered disk".utf8)
        let auxiliary = Data("registered auxiliary storage".utf8)
        let hardware = Data("registered hardware model".utf8)
        let identity = TemplateIdentity(
            schemaVersion: 1,
            version: "verification-boundary-v1",
            guestOs: "macos",
            architecture: hostArchitecture(),
            diskMib: 1,
            diskSha256: SHA256.hash(data: disk).hex,
            auxiliaryStorageSha256: SHA256.hash(data: auxiliary).hex,
            hardwareModelSha256: SHA256.hash(data: hardware).hex,
            bootstrapProtocol: 1,
            bootstrapPort: 22022,
            processLimit: 512,
            processLimitMechanism: "rlimit_nproc_dedicated_uid"
        )
        let manifest = try TemplateManifest.make(identity: identity)
        let directory = store.templateDirectory(manifest.templateDigest)
        try ensureDirectory(directory)
        try disk.write(to: directory.appendingPathComponent(Store.diskName))
        try auxiliary.write(to: directory.appendingPathComponent(Store.auxiliaryName))
        try hardware.write(to: directory.appendingPathComponent(Store.hardwareModelName))
        try writeFile(manifest, to: directory.appendingPathComponent(Store.manifestName))

        XCTAssertEqual(try store.verifyTemplate(image: manifest.image), manifest)
        try Data("tampered disk".utf8).write(
            to: directory.appendingPathComponent(Store.diskName)
        )

        XCTAssertEqual(
            try store.loadTemplate(image: manifest.image).0,
            manifest,
            "readiness uses the already-verified pinned inventory instead of rehashing artifacts"
        )
        XCTAssertThrowsError(try store.verifyTemplate(image: manifest.image)) { error in
            XCTAssertEqual((error as? HelperFailure)?.message, "template artifact identity mismatch")
        }
    }

    func testPublicRecordRedactsRecoveryFieldsAndEmitsNullExitCode() throws {
        let record = fixtureRecord()
        let data = try protocolEncoder.encode(record.publicRecord())
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertNil(json["_supervisor_pid"])
        XCTAssertNil(json["_supervisor_token"])
        XCTAssertTrue(json["runner_exit_code"] is NSNull)
        XCTAssertEqual(json["shared_host_paths"] as? [String], [])
    }

    func testOptionsRejectUnknownAndDuplicateArguments() throws {
        XCTAssertThrowsError(try Options(["--secret", "value"], values: ["--image"], flags: []))
        XCTAssertThrowsError(try Options(["--json", "--json"], values: [], flags: ["--json"]))
        let options = try Options(["--image", "pinned", "--json"], values: ["--image"], flags: ["--json"])
        XCTAssertEqual(try options.required("--image"), "pinned")
        XCTAssertTrue(options.has("--json"))
    }

    func testGuestHeaderContainsLengthsAndNoJITDocument() throws {
        let header = GuestStartHeader(
            protocolVersion: 1,
            command: "start-runner",
            environmentId: "rm-attempt-generation",
            generation: "generation",
            runnerArchiveBytes: 123,
            runnerArchiveSha256: String(repeating: "a", count: 64),
            jitBytes: 17,
            processLimit: 512,
            processLimitMechanism: "rlimit_nproc_dedicated_uid"
        )
        let encoded = String(decoding: try protocolEncoder.encode(header), as: UTF8.self)
        XCTAssertFalse(encoded.contains("encoded-jit-secret"))
        XCTAssertTrue(encoded.contains("\"jit_bytes\":17"))
    }

    private func fixtureRecord() -> EnvironmentRecord {
        EnvironmentRecord(
            protocolVersion: 1,
            environmentId: "rm-attempt-generation",
            state: .prepared,
            hostId: "00000000-0000-0000-0000-000000000001",
            attemptId: "00000000-0000-0000-0000-000000000002",
            generation: "generation",
            image: "vm-version:v1@sha256:\(String(repeating: "a", count: 64))",
            templateDigest: String(repeating: "a", count: 64),
            guestOs: "macos",
            architecture: hostArchitecture(),
            writableDiskId: "disk",
            freshWritableDisk: true,
            sharedHostPaths: [],
            jitChannel: "private",
            appliedCpuMillis: 2_000,
            appliedMemoryMib: 4_096,
            appliedDiskMib: 32_768,
            appliedProcessLimit: 512,
            runnerExitCode: nil,
            supervisorPid: 123,
            supervisorToken: "token"
        )
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("runner-manager-macos-vm-protocol-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }
}
