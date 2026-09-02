import Foundation

/// Built-in fake policy check used when no scan endpoint is configured.
/// Sleeps, then returns a verdict — so the hold + allow/block path can be
/// exercised without a real API.
enum FileScanner {
    static var delaySeconds: TimeInterval = 10
    /// Simulated scanner result. Set `--scan-reject` to test the block path.
    static var simulatedVerdict: Verdict = .allow

    enum Verdict: String {
        case allow
        case deny
    }

    struct Event: Codable {
        let timestamp: Date
        let event: String
        let pid: Int32
        let process: String
        let path: String
        let verdict: String?
        let delaySeconds: TimeInterval?
    }

    private static let queue = DispatchQueue(
        label: "com.minifilter.scan",
        qos: .userInitiated,
        attributes: .concurrent
    )

    /// Call `onStart` immediately, wait `delaySeconds`, then `onStop` with the verdict.
    static func scan(
        onStart: @escaping () -> Void,
        onStop: @escaping (Verdict) -> Void
    ) {
        onStart()
        queue.asyncAfter(deadline: .now() + delaySeconds) {
            onStop(simulatedVerdict)
        }
    }
}
