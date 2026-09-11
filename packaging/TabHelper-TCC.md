# MiniFilter tab helper — TCC

Grant **Accessibility** to **MiniFilterTabHelper**, never to `sudo MiniFilter`.
That is enough for a tab **title**. The helper does not use Screen Recording or
Automation (no window-list names, no AppleScript URL).

| Permission | System Settings | Why |
| --- | --- | --- |
| Accessibility | Privacy & Security → Accessibility | AX window title, keyed by the ES event PID |

The helper does **not** need Full Disk Access or the Endpoint Security
entitlement. Chromium History / `Session_*` stay in the root ES process.

## Identity

TCC keys off the signed helper binary (and its embedded Info.plist
`CFBundleIdentifier` `com.minifilter.tabhelper`). Rebuilds under `.build/`
look like a new app; copy the binary to a stable path before granting:

```bash
./run_tabhelper.sh --install
```

That installs `/usr/local/libexec/MiniFilterTabHelper` and a LaunchAgent so
the helper runs as the Aqua user (not as root, not as a Terminal child).
If you instead run `MiniFilter --tab-helper` from Terminal, macOS may attribute
Accessibility to Terminal.

## Local test (no sudo, no install)

```bash
./run_tabhelper.sh
# or: swift run MiniFilterTabHelper
# or: MiniFilter --tab-helper
```

Then, in another terminal: `sudo MiniFilter --esmonitor`. On helper miss or
timeout (300ms) the ES log line is unchanged — no tab suffix, no error line.
