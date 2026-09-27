import Foundation
import XCTest
@testable import RunnerManagerMacOSVM

final class GuestListenerTests: XCTestCase {
    func testInvocationIsRestrictedToTheDedicatedGuestUidAndRunCommand() {
        let executable = URL(fileURLWithPath: "/guest/bin/Runner.Listener")
        XCTAssertTrue(isGuestListenerInvocation(executable: executable, arguments: ["run"], uid: 499, effectiveUID: 499))
        for uid: uid_t in [0, 501] {
            XCTAssertFalse(isGuestListenerInvocation(executable: executable, arguments: ["run"], uid: uid, effectiveUID: uid))
        }
        XCTAssertFalse(isGuestListenerInvocation(executable: executable, arguments: ["run"], uid: 499, effectiveUID: 0))
        XCTAssertFalse(isGuestListenerInvocation(executable: executable, arguments: ["configure"], uid: 499, effectiveUID: 499))
        XCTAssertFalse(isGuestListenerInvocation(executable: URL(fileURLWithPath: "/helper"), arguments: ["run"], uid: 499, effectiveUID: 499))
    }

    func testFailureClassificationReturnsOnlyClosedCodes() {
        for (input, expected): (String, GuestListenerFailure) in [
            ("Access to the path /private/secret is denied", .permission),
            ("Input is not a valid Base-64 string: secret", .configuration),
            ("A fatal error: secret", .runtime),
            ("CryptographicException: keychain secret", .security),
            ("arbitrary guest output token=secret", .unknown),
        ] {
            XCTAssertEqual(GuestListenerFailure.classify(Data(input.utf8)), expected)
        }
        XCTAssertEqual(GuestListenerFailure.allCases.map { $0.rawValue }, [110, 111, 112, 113, 114])
    }

    func testOutputCaptureIsBoundedAndErasedAfterClassification() throws {
        let pipe = Pipe()
        let capture = BoundedGuestOutput()
        let writer = DispatchQueue(label: "guest-output-test")
        writer.async {
            try? pipe.fileHandleForWriting.write(contentsOf: Data(repeating: 120, count: 256 * 1024))
            try? pipe.fileHandleForWriting.close()
        }
        capture.drain(pipe.fileHandleForReading)
        XCTAssertEqual(capture.retainedByteCount, BoundedGuestOutput.limit)
        XCTAssertEqual(capture.classificationAndErase(), .unknown)
        XCTAssertEqual(capture.retainedByteCount, 0)
        XCTAssertEqual(capture.classificationAndErase(), .unknown)
    }

    func testSuccessfulChildPreservesZeroAndFailureReturnsOnlyACategory() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("guest-listener-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let real = root.appendingPathComponent(guestRealListenerName)
        let wrapper = root.appendingPathComponent("Runner.Listener")
        for (script, expected): (String, Int32) in [
            ("#!/bin/sh\n[ \"$1\" = run ] || exit 99\nexit 0\n", 0),
            ("#!/bin/sh\nprintf 'Permission denied: token=synthetic' >&2\nexit 1\n", 110),
        ] {
            try Data(script.utf8).write(to: real)
            try setPermissions(real, mode: 0o700)
            XCTAssertEqual(guestListenerExitCode(executable: wrapper), expected)
        }
    }

    func testArchiveOverlayPreservesTheSourceAndOriginalListenerBytes() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("guest-overlay-test-" + UUID().uuidString)
        try ensureDirectory(root)
        defer { try? FileManager.default.removeItem(at: root) }
        let source = root.appendingPathComponent("source")
        let bin = source.appendingPathComponent("bin")
        try ensureDirectory(source)
        try ensureDirectory(bin)
        let listener = bin.appendingPathComponent("Runner.Listener")
        let original = Data("#!/bin/sh\nexit 0\n".utf8)
        try original.write(to: listener)
        try setPermissions(listener, mode: 0o700)
        let archive = root.appendingPathComponent("runner.tar")
        try archiveRunner(source: source, destination: archive, overlayListener: true)
        try appendGuestListener(source: source, archive: archive)
        XCTAssertEqual(try Data(contentsOf: listener), original)
        let unpacked = root.appendingPathComponent("unpacked")
        try ensureDirectory(unpacked)
        let tar = Process()
        tar.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
        tar.arguments = ["-C", unpacked.path, "-xf", archive.path]
        try tar.run()
        tar.waitUntilExit()
        XCTAssertEqual(tar.terminationStatus, 0)
        XCTAssertEqual(try Data(contentsOf: unpacked.appendingPathComponent("bin/" + guestRealListenerName)), original)
        XCTAssertEqual(try Data(contentsOf: unpacked.appendingPathComponent("bin/Runner.Listener")),
                       try Data(contentsOf: XCTUnwrap(Bundle.main.executableURL)))
        XCTAssertEqual(try sha256(url: unpacked.appendingPathComponent("bin/Runner.Listener")),
                       try sha256(url: XCTUnwrap(Bundle.main.executableURL)))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent(".listener-overlay").path))
    }

    func testMissingArtifactCannotHashAsAnEmptyFile() throws {
        let absent = FileManager.default.temporaryDirectory.appendingPathComponent("absent-" + UUID().uuidString)
        XCTAssertThrowsError(try sha256(url: absent))
    }

    func testJitStaysInChildEnvironmentAndIsErasedFromWrapperEnvironment() throws {
        let key = "ACTIONS_RUNNER_INPUT_JITCONFIG"
        guard getenv(key) == nil else {
            XCTFail("refusing to overwrite a pre-existing one-time input")
            return
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("guest-jit-test-" + UUID().uuidString)
        try ensureDirectory(root)
        defer {
            unsetenv(key)
            try? FileManager.default.removeItem(at: root)
        }
        let real = root.appendingPathComponent(guestRealListenerName)
        let script = "#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = run ] && [ \"$ACTIONS_RUNNER_INPUT_JITCONFIG\" = synthetic-nonsecret ] || exit 1\nexit 0\n"
        try Data(script.utf8).write(to: real)
        try setPermissions(real, mode: 0o700)
        setenv(key, "synthetic-nonsecret", 1)
        XCTAssertEqual(guestListenerExitCode(executable: root.appendingPathComponent("Runner.Listener")), 0)
        XCTAssertNil(getenv(key))
    }

    func testStoppedCaptureDoesNotWaitForAnUnrelatedOpenWriter() {
        let pipe = Pipe()
        defer { try? pipe.fileHandleForWriting.close() }
        let capture = BoundedGuestOutput()
        capture.requestStop()
        let start = Date()
        capture.drain(pipe.fileHandleForReading)
        XCTAssertLessThan(Date().timeIntervalSince(start), 1)
        XCTAssertEqual(capture.retainedByteCount, 0)
    }
}
