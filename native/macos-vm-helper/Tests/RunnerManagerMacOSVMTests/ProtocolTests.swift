import Foundation
import XCTest
@testable import RunnerManagerMacOSVM

final class ProtocolTests: XCTestCase {
    func testPinnedImageParserRejectsMutableAndNonCanonicalReferences() throws {
        let digest = String(repeating: "a", count: 64)
        XCTAssertEqual(try parsePinnedImage("vm-version:macos-15-arm64-v1@sha256:\(digest)").digest, digest)
        for invalid in [
            "latest",
            "vm-version:latest",
            "vm-version:v1@sha256:ABC",
            "vm-version:../v1@sha256:\(digest)",
            "vm-version:v1@sha256:\(String(repeating: "g", count: 64))",
        ] {
            XCTAssertThrowsError(try parsePinnedImage(invalid), invalid)
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
}
