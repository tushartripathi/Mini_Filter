import Foundation
import MiniFilterCore

@main
enum MiniFilter {
    static func main() {
        let args = CommandLine.arguments
        if args.contains("--esmonitor") {
            EndpointSecurityMonitor.run(arguments: args)
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
