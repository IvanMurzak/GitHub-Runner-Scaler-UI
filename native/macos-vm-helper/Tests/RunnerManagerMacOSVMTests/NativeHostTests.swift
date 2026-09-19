import Darwin
import Foundation
import XCTest
@testable import RunnerManagerMacOSVM

final class NativeHostTests: XCTestCase {
    func testAPFSCloneCreatesIndependentWritableFile() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("source")
        let clone = root.appendingPathComponent("clone")
        try Data("source-data".utf8).write(to: source)

        try cloneFile(source, clone)
        XCTAssertEqual(try Data(contentsOf: clone), Data("source-data".utf8))

        let handle = try FileHandle(forWritingTo: clone)
        try handle.write(contentsOf: Data("changed".utf8))
        try handle.close()
        XCTAssertEqual(try Data(contentsOf: source), Data("source-data".utf8))
        XCTAssertNotEqual(try Data(contentsOf: clone), try Data(contentsOf: source))
    }

    func testCloneCapabilityProbeRemovesEveryProbeArtifact() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        XCTAssertTrue(supportsFreshClones(in: root))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: root.path), [])
    }

    func testPrivateChannelFrameRoundTripAndPeerClose() throws {
        var sockets = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            for descriptor in sockets where descriptor >= 0 { Darwin.close(descriptor) }
        }

        let reply = GuestReply(
            protocolVersion: protocolVersion,
            status: "accepted",
            environmentId: "rm-attempt-generation",
            generation: "generation",
            appliedProcessLimit: UInt32(requiredProcessLimit),
            processLimitMechanism: "rlimit_nproc_dedicated_uid",
            runnerUidExclusive: true,
            runnerPid: 42,
            runnerExitCode: nil
        )
        let payload = try protocolEncoder.encode(reply)
        let deadline = Date().addingTimeInterval(2)
        try writeUInt32(sockets[0], UInt32(payload.count), deadline: deadline)
        try writeAll(sockets[0], data: payload, deadline: deadline)

        let decoded = try readReply(sockets[1], deadline: deadline)
        XCTAssertEqual(decoded.status, "accepted")
        XCTAssertEqual(decoded.environmentId, "rm-attempt-generation")
        XCTAssertEqual(decoded.appliedProcessLimit, UInt32(requiredProcessLimit))

        Darwin.close(sockets[0])
        sockets[0] = -1
        XCTAssertThrowsError(try readExact(sockets[1], count: 1, deadline: deadline)) { error in
            XCTAssertEqual((error as? HelperFailure)?.message, "private guest channel closed")
        }
    }

    func testPrivateChannelReadHonorsDeadlineAndClosesCleanly() throws {
        var sockets = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer {
            for descriptor in sockets where descriptor >= 0 { Darwin.close(descriptor) }
        }

        let started = Date()
        XCTAssertThrowsError(
            try readExact(sockets[0], count: 1, deadline: Date().addingTimeInterval(0.05))
        ) { error in
            XCTAssertEqual((error as? HelperFailure)?.message, "private guest channel timed out")
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("runner-manager-native-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }
}
