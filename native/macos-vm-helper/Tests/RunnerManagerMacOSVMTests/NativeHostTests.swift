import Darwin
import CoreGraphics
import Foundation
import XCTest
@testable import RunnerManagerMacOSVM

final class NativeHostTests: XCTestCase {
    func testUserSessionRequiresCompletedConsoleLoginAndMatchingNonRootIdentity() {
        let session: [String: Any] = [
            kCGSessionOnConsoleKey as String: true,
            kCGSessionLoginDoneKey as String: true,
            kCGSessionUserIDKey as String: 501,
        ]
        XCTAssertTrue(isLoggedInUserSession(session, realUID: 501, effectiveUID: 501))
        XCTAssertFalse(isLoggedInUserSession(nil, realUID: 501, effectiveUID: 501))
        XCTAssertFalse(isLoggedInUserSession(session, realUID: 0, effectiveUID: 0))
        XCTAssertFalse(isLoggedInUserSession(session, realUID: 501, effectiveUID: 0))
        XCTAssertFalse(isLoggedInUserSession(session, realUID: 502, effectiveUID: 502))
        for key in [kCGSessionOnConsoleKey, kCGSessionLoginDoneKey] {
            var incomplete = session
            incomplete[key as String] = false
            XCTAssertFalse(isLoggedInUserSession(incomplete, realUID: 501, effectiveUID: 501))
            incomplete.removeValue(forKey: key as String)
            XCTAssertFalse(isLoggedInUserSession(incomplete, realUID: 501, effectiveUID: 501))
        }
    }

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

    func testHandoffHasItsOwnBudgetButCannotReviveAnExpiredBoot() throws {
        let boot = Date(timeIntervalSince1970: 1000)
        let connection = boot.addingTimeInterval(operationTimeout - 1)
        XCTAssertEqual(
            try guestHandoffDeadline(bootDeadline: boot.addingTimeInterval(operationTimeout), now: connection),
            connection.addingTimeInterval(guestHandoffTimeout)
        )
        XCTAssertThrowsError(try guestHandoffDeadline(bootDeadline: boot, now: boot))
        XCTAssertThrowsError(try guestHandoffDeadline(bootDeadline: boot, now: boot.addingTimeInterval(1)))
    }

    func testLatePrivateConnectionIsClosedInsteadOfLeaked() {
        var closed = [Int]()
        let pending = PendingGuestConnection<Int> { closed.append($0) }
        XCTAssertNil(pending.wait(timeout: .now()))
        pending.complete(42)
        XCTAssertEqual(closed, [42])
    }

    func testTimelyPrivateConnectionIsAdoptedWithoutClosingIt() {
        var closed = [Int]()
        let pending = PendingGuestConnection<Int> { closed.append($0) }
        pending.complete(42)
        XCTAssertEqual(pending.wait(timeout: .now() + 1), 42)
        XCTAssertTrue(closed.isEmpty)
    }

    func testBackpressuredPrivateChannelWriteHonorsItsDeadline() throws {
        var sockets = [Int32](repeating: -1, count: 2)
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { sockets.forEach { Darwin.close($0) } }
        // Verify the real API sets nonblocking mode before testing a full
        // socket. This guard keeps a regression from hanging the test suite.
        try writeAll(sockets[0], data: Data([1]), deadline: Date().addingTimeInterval(1))
        guard fcntl(sockets[0], F_GETFL) & O_NONBLOCK != 0 else {
            XCTFail("private writer left a blocking descriptor")
            return
        }
        let started = Date()
        XCTAssertThrowsError(try writeAll(
            sockets[0], data: Data(repeating: 1, count: 1024 * 1024),
            deadline: started.addingTimeInterval(0.05)
        )) { error in
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
