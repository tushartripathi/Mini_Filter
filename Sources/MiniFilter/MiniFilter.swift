import Foundation
import MiniFilterCore

@main
enum MiniFilter {
    static func main() {
        let args = CommandLine.arguments
        if args.contains("--esmonitor") {
            EndpointSecurityMonitor.run(arguments: args)
        }

        if let idx = args.firstIndex(of: "--resume-hold"),
           args.count > idx + 1,
           let pid = Int32(args[idx + 1]) {
            let threadId = args.count > idx + 2 ? UInt64(args[idx + 2]) : nil
            ProcessHold.forceResume(pid: pid, threadId: threadId)
            exit(0)
        }

        fputs(
            """
            MiniFilter Endpoint Security PoC

              ./run_esmonitor.sh [--process NAME] [--seconds N] [--json] [--verbose] [--all-files] [--scan-reject]

            Default watches every user app. Examples:

              sudo MiniFilter --esmonitor
              sudo MiniFilter --esmonitor --process WhatsApp --seconds 60

            """,
            stderr
        )
        exit(2)
    }
}
