import Darwin
import Foundation

// Closed wrapper exits, not upstream output. The pinned bootstrap already
// transports its child's exit status over the private channel.
enum GuestListenerFailure: Int32, CaseIterable {
    case permission = 110
    case configuration = 111
    case runtime = 112
    case security = 113
    case unknown = 114

    static func classify(_ data: Data) -> Self {
        let text = String(decoding: data, as: UTF8.self).lowercased()
        if text.contains("permission denied") || text.contains("access to the path") {
            return .permission
        }
        if text.contains("base-64") || text.contains("runner is not configured") ||
            text.contains("invalid jit") || text.contains("jsonreaderexception") {
            return .configuration
        }
        if text.contains("libhostfxr") || text.contains("libhostpolicy") ||
            text.contains("failed to load") || text.contains("fatal error") {
            return .runtime
        }
        if text.contains("keychain") || text.contains("cryptographicexception") ||
            text.contains("seckey") || text.contains("interaction is not allowed") {
            return .security
        }
        return .unknown
    }
}

final class BoundedGuestOutput {
    static let limit = 64 * 1024
    private let lock = NSLock()
    private var data = Data()
    private var stopped = false

    var retainedByteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return data.count
    }

    func drain(_ handle: FileHandle) {
        defer { try? handle.close() }
        while true {
            lock.lock()
            let finished = stopped
            let full = data.count == Self.limit
            lock.unlock()
            if finished && full { break }
            var descriptor = pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, finished ? 0 : 200)
            if ready < 0 {
                if errno == EINTR { continue }
                break
            }
            if ready == 0 {
                if finished { break }
                continue
            }
            if descriptor.revents & Int16(POLLNVAL) != 0 { break }
            guard var chunk = try? handle.read(upToCount: 16 * 1024), !chunk.isEmpty else { break }
            lock.lock()
            data.append(chunk.prefix(max(0, Self.limit - data.count)))
            lock.unlock()
            chunk.resetBytes(in: 0..<chunk.count)
        }
    }

    func requestStop() {
        lock.lock()
        stopped = true
        lock.unlock()
    }

    func classificationAndErase() -> GuestListenerFailure {
        lock.lock()
        defer { lock.unlock() }
        let result = GuestListenerFailure.classify(data)
        data.resetBytes(in: 0..<data.count)
        data.removeAll(keepingCapacity: false)
        return result
    }
}

let guestRealListenerName = ".Runner.Listener.rmv1-real"

func isGuestListenerInvocation(executable: URL, arguments: [String], uid: uid_t, effectiveUID: uid_t) -> Bool {
    executable.lastPathComponent == "Runner.Listener" && arguments == ["run"] &&
        uid == 499 && effectiveUID == uid
}

func guestListenerExitCode(executable: URL) -> Int32 {
    let real = executable.deletingLastPathComponent().appendingPathComponent(guestRealListenerName)
    guard isRegularFile(real), FileManager.default.isExecutableFile(atPath: real.path) else {
        return GuestListenerFailure.runtime.rawValue
    }
    let child = Process()
    child.executableURL = real
    child.arguments = ["run"]
    // Save the child's input, then erase the wrapper's OS-visible environment.
    // No JIT is placed in argv, output, files or diagnostics.
    child.environment = ProcessInfo.processInfo.environment
    if let jit = getenv("ACTIONS_RUNNER_INPUT_JITCONFIG") {
        memset(jit, 0, strlen(jit))
        unsetenv("ACTIONS_RUNNER_INPUT_JITCONFIG")
    }
    child.standardInput = FileHandle.nullDevice
    let stdout = Pipe(), stderr = Pipe()
    child.standardOutput = stdout
    child.standardError = stderr
    let capture = BoundedGuestOutput()
    let drained = DispatchGroup()
    do { try child.run() } catch { return GuestListenerFailure.runtime.rawValue }
    try? stdout.fileHandleForWriting.close()
    try? stderr.fileHandleForWriting.close()
    for handle in [stdout.fileHandleForReading, stderr.fileHandleForReading] {
        drained.enter()
        DispatchQueue.global().async {
            capture.drain(handle)
            drained.leave()
        }
    }
    child.waitUntilExit()
    // A descendant may retain a pipe writer after the listener exits. Drain
    // already available bounded data, but never wait indefinitely for its EOF.
    capture.requestStop()
    drained.wait()
    let failure = capture.classificationAndErase()
    if child.terminationReason == .exit && child.terminationStatus == 0 { return 0 }
    return failure.rawValue
}
