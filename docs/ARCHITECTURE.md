# MiniFilter — from idea to execution

This document describes **what the project does now**, how the idea turned into a running system, and the pieces you will see in logs. Key concepts are defined in their own section so they are not mixed into the flow.

The live product in this repo is a **macOS CLI**: Endpoint Security watches file opens/copies system-wide, infers upload vs download, optionally **holds** the syscall while a scan runs, and annotates browser transfers with tab title/URL when it can.

The original README still describes an earlier **WhatsApp Desktop SwiftUI** monitor (ChatStorage + FSEvents). That is the historical starting point. The code you run today is `./run_esmonitor.sh`.

---

## 1. The idea

**Problem.** Data-loss prevention on Mac cannot read WhatsApp or Chrome HTTPS bodies. Encryption and sandboxing hide the payload. You also cannot reliably scrape another app’s private files as a production design.

**Insight.** The kernel *does* see the moment a process opens, clones, or writes a file. If you sit on that event, you know:

- which **process** (Chrome, WhatsApp, Mail, …)
- which **path** on disk
- roughly whether it looks like an **upload** (user file copied into an app) or a **download** (app writes into Desktop/Downloads)

You still do not see the network bytes. Confirmed “this HTTPS POST was that file” would need a Network Extension later. MiniFilter is the **file half**.

**Secondary problem.** Endpoint Security only names the process, not the Chrome tab. A log that says `Google Chrome[1195] '/Users/…/shot.png'` is incomplete. The page title and URL have to be recovered from somewhere else.

**Constraint that drives the whole design.** The ES client **must run as root**. Root usually **cannot** use TCC-gated UI APIs (window titles, AppleScript to Chrome). Root **can** read Chrome’s profile on disk if Full Disk Access is granted. Those are two different sources of “which tab”.

---

## 2. High-level design (HLD)

Two processes, one job: see the file transfer, optionally delay it, log it.

```
                    ┌─────────────────────────────────────────┐
                    │  User apps: Chrome, Safari, WhatsApp…   │
                    │  open / clone / copy a user file        │
                    └────────────────────┬────────────────────┘
                                         │ syscalls
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │  macOS kernel — Endpoint Security AUTH  │
                    │  holds OPEN/CLONE/COPYFILE ~15s max     │
                    └────────────────────┬────────────────────┘
                                         │ es_message (must reply)
                                         ▼
 ┌──────────────┐   Unix socket    ┌──────────────────────────────────┐
 │ Tab helper   │◄──optional──────►│  MiniFilter (ROOT)               │
 │ Aqua user    │  300ms timeout   │  ./run_esmonitor.sh              │
 │ NOT required │                  │                                  │
 │ for Chrome   │                  │  1. Classify path                │
 │ Session hits │                  │  2. Correlate → UPLOAD/DOWNLOAD  │
 └──────────────┘                  │  3. Resolve tab (disk, then live)│
                                   │  4. HOLD + scan (17s simulated)  │
                                   │  5. ALLOW/DENY AUTH              │
                                   │  6. Freeze thread if scan > AUTH │
                                   └──────────────────────────────────┘
                                         │
                                         ▼
                              stdout + ~/Library/Logs/MiniFilter/
```

### What each process is allowed to do

| Process | Privilege | What it does | What it must not do |
| --- | --- | --- | --- |
| `MiniFilter --esmonitor` | **root** | Subscribe to ES, hold syscalls, read Chrome files on disk, scan, ALLOW/DENY | Drop root; wait 15s+ on a hung UI script; move ES into a user process |
| `MiniFilterTabHelper` | **logged-in Aqua user** | Window **title** via Accessibility (AX), keyed by PID | Run as sudo; block AUTH; become an ES client; Screen Recording / Automation |

They talk over a **localhost Unix socket** (`/tmp/minifilter-tabhelper-<uid>.sock`). If the helper is absent, root continues. Logs just omit live window data. Chrome **Session_*** on disk still works — that is why you already see Gmail URLs without the helper running.

### Production shape (not built yet)

A shippable product would be a **system extension** (ES + later Network Extension) talking XPC to a UI, with Apple-granted entitlements. This repo is a SIP-off CLI PoC of the file/AUTH path.

---

## 3. From idea to execution (the story of a file)

Example: you attach a Desktop PNG in Gmail in Chrome.

1. Chrome issues `open()` / `clone()` on `/Users/work/Desktop/Screenshot ….png`.
2. The kernel does **not** complete that syscall. It sends MiniFilter an **AUTH** event with a ~15 second deadline.
3. MiniFilter checks: user-facing file? user app (not Finder)? not already allowed two seconds ago?
4. It classifies this as an **UPLOAD** (user file leaving Desktop into Chrome’s world).
5. It looks up the tab:
   - Chrome profile `Session_*` on disk → often already has `Inbox … Gmail` + `https://mail.google.com/…`
   - only if that is incomplete: ask the user helper (PID-keyed AX **title** only)
   - miss or timeout: log **without** a tab suffix; no error line
6. It prints `UPLOAD`, then `HOLD`, then `SCAN START`.
7. The simulated scanner sleeps **17 seconds**. Usable AUTH is ~13 seconds. MiniFilter **replies ALLOW/DENY before the kernel kills the client**, and **suspends the issuing Mach thread** for the remaining scan time so Chrome cannot use the file yet.
8. `SCAN STOP` + verdict. Thread resumes. Chrome proceeds or is denied.
9. A follow-up OPEN/CLONE of the same path within ~2 seconds is not scanned again (`VerdictCache`).

That is the log you saw at 12:38. The website name came from **step 5 (disk)**, not from `run_tabhelper.sh`.

---

## 4. Low-level design (LLD)

### 4.1 Package layout

| Target | Path | Role |
| --- | --- | --- |
| `MiniFilterCore` | `Sources/MiniFilter/Core/` | All logic |
| `MiniFilter` | `Sources/MiniFilter/MiniFilter.swift` | CLI: `--esmonitor`, `--tab-helper`, `--resume-hold` |
| `MiniFilterTabHelper` | `Sources/MiniFilterTabHelper/` | User-level socket server |
| Tests | `Tests/MiniFilterCoreTests/` | Correlator, gate, tab suffix, helper timeout |

Entry scripts:

- `./run_esmonitor.sh` — build, ad-hoc sign with ES entitlement, `sudo MiniFilter --esmonitor`
- `./run_tabhelper.sh` — build helper, run as **you** (optional `--install` LaunchAgent)

### 4.2 Event pipeline (`EndpointSecurityMonitor`)

Subscribe (AUTH, not notify-only):

- `AUTH_OPEN`, `AUTH_CLONE`, `AUTH_COPYFILE` — can delay or deny
- `NOTIFY_CREATE`, `NOTIFY_WRITE`, `NOTIFY_CLOSE`, `NOTIFY_RENAME`, … — correlation only

On each callback (`handle`):

1. Extract pid, process name, path, destination, open flags.
2. Ignore noise (our own logs, caches, `.DS_Store`, …).
3. Optionally keep only **user-facing extensions** (`FileClassifier`).
4. If path is in the deny cache → `BLOCKED`, AUTH deny.
5. If this OPEN/CLONE should be gated → `browserPage()` + `recordUpload()` + `UploadGate.holdSyscall()` (retain the ES message, reply later).
6. Else `TransferCorrelator.observe()` may emit a DOWNLOAD (or a non-gated UPLOAD).
7. Always reply to AUTH unless the message was retained for a scan. **A missed AUTH reply kills this ES client.**

Log format (human):

```
[time] UPLOAD     Process[pid]  'path'  tab 'Title'  https://…
[time] HOLD       Process[pid]  'path'  tab '…'  scan 17.0s; thread N suspended …
[time] SCAN START …
[time] SCAN STOP  …  allow (simulated, 17.0s)
```

`tab '…'  url` is `BrowserTab.logSuffix`. Empty page → those two fields are omitted. JSONL is also written under `~/Library/Logs/MiniFilter/`.

### 4.3 Upload vs download (`TransferCorrelator`)

ES does not say “upload”. The correlator infers:

| Pattern | Direction | Path logged |
| --- | --- | --- |
| User source (Desktop/Documents/…) cloned into an **app container** | upload | the **original** user path |
| App writes a user-facing file to Desktop/Downloads/Documents | download | the destination |
| Write into an app media store, and this pid did not just upload | download | that media path |
| OPEN of a user file (read) | remembered | used to attribute a later WRITE |

Deduped for ~15s so one attach does not spam. `--verbose` prints raw OPEN/CLONE/WRITE lines before inference.

### 4.4 Hold, scan, freeze (`UploadGate`, `FileScanner`, `ProcessHold`, `VerdictCache`)

```
AUTH arrives
    │
    ├─ shouldGate?  skip Finder, Spotlight, QuickLook, iCloud agents
    ├─ shouldHoldOpen / shouldHoldCopy?  user source, or copy into container
    ├─ wasAllowed(path) within 2s?  skip (same send’s follow-up clone)
    │
    ├─ HOLD log
    ├─ retain es_message
    ├─ FileScanner.scan (default 17s, then allow; --scan-reject → deny)
    │
    ├─ usable AUTH window ≈ deadline − 2s margin  (~13s)
    ├─ if scan > usable window:
    │     ProcessHold.freeze(issuing thread)   // thread_suspend
    │     else SIGSTOP whole process
    │     reply ALLOW/DENY before kernel timeout  (fail-open if we miss)
    │     wait remainder of scan
    │     thaw
    └─ else: wait scan, then reply ALLOW/DENY
```

Deny is remembered for the process lifetime. Allow is reused for **2 seconds** so OPEN then CLONE of the same attach is one scan.

The scanner today is **fake**: sleep, then allow/deny. A real HTTP policy API is the intended next plug-in at `FileScanner`.

### 4.5 Browser tab / URL (`BrowserTab`, `ChromiumSession`, `TabHelper`)

`EndpointSecurityMonitor.browserPage()` always calls `BrowserTab.current(process, pid, path, direction)`.

Order inside `current`:

```
1. Cache (~2.5s per pid)
2. If this process is a known browser:
   a. DOWNLOAD only: Chromium History SQLite  (downloads.tab_url)
   b. Chromium Session_* SNSS file on disk    (last active tab)
   c. Live lookup:
        if helper socket exists → query (≤ 300ms, no print on miss)
        else in-process AX title (Accessibility)
3. Merge: disk URL + live title when both exist
4. logSuffix →  tab 'Title'  url   or  ""
```

**Disk (works as root, no helper).** Chrome/Edge/Brave write `Session_*` under `~/Library/Application Support/…`. MiniFilter parses SNSS and takes the most recently active tab. That is how Gmail title + URL appear while `MiniFilterTabHelper` is **not** running.

**Live (needs the Aqua user + Accessibility).** Keyed by the **ES event PID**, walking parents (Chrome Helper → Google Chrome). **Not** `NSWorkspace.frontmostApplication` — during upload the focused window is often the file picker `"Open"`. Titles `"Open"` / `"Save"` / empty / bare app name are skipped. Title comes from AX (`AXUIElementCreateApplication(pid)`). The helper does **not** use Screen Recording or Automation, so it does not fetch a live URL.

Helper protocol: one JSON line each way, socket mode `0600`, cache ~2s per pid. Client never waits more than 400ms. Hung helper must not eat the 15s AUTH budget.

TCC: grant **Accessibility** to **MiniFilterTabHelper**, never to `sudo MiniFilter`. Notes: `packaging/TabHelper-TCC.md`.

### 4.6 File allowlist (`FileClassifier`)

Only extensions a person would recognise (png, pdf, …). Internal `.dat` / `.enc` / journals are ignored. “User source” means under `/Users/…` but **not** inside Containers / Group Containers. “User destination” is Desktop/Downloads/Documents/….

---

## 5. Key concepts (standalone)

### Endpoint Security (ES)

Apple kernel framework. A privileged client gets a callback when processes touch files. **AUTH** events pause the syscall until the client replies ALLOW/DENY (or flags for OPEN). **NOTIFY** events are informational. Requires **root**, **Full Disk Access**, and entitlement `com.apple.developer.endpoint-security.client` (restricted; local PoC: SIP off + ad-hoc sign).

### AUTH deadline (~15 seconds)

If MiniFilter does not reply in time, macOS **kills the ES client** and the syscall typically **fails open** (the app proceeds). Therefore a 17s scan cannot sit on the AUTH message the whole time. Reply early, freeze the thread for the rest.

### Upload vs download (inferred)

Not a kernel fact. Heuristic: user file → app sandbox ≈ upload; app → Desktop/Downloads ≈ download. Network confirmation is out of scope.

### User-facing file

Allowlisted extension. Stops the log filling with app internals.

### Hold / gate

Deliberately stalling the file open/copy until a scan verdict. Finder/Spotlight are excluded so the Mac stays usable.

### Thread suspend vs SIGSTOP

`thread_suspend` freezes **only** the thread that issued the syscall (Chrome’s file-picker thread). The rest of Chrome can still paint. `SIGSTOP` stops the **whole process** — last resort if the Mach thread cannot be found. Watchdog exists so a crash cannot leave Chrome frozen.

### Verdict cache

Deny sticks. Allow is short-lived (2s) so one user action that generates OPEN+CLONE is one scan, but attaching the same file later is scanned again.

### TCC (Transparency, Consent, Control)

macOS privacy prompts. Bound to a **code identity** (path + signature). Root ES and the user’s helper are different identities. The helper only needs **Accessibility**. Granting FDA to MiniFilter does **not** grant window titles.

### Chromium Session / History (on disk)

Chrome persists tabs in `Session_*` (SNSS) and download rows in `History` (`tab_url`). Readable by a root FDA process. Independent of window titles. Can be slightly stale vs the window you see, but is why Gmail URLs show up without the helper.

### Live tab helper

Optional user daemon. Answers “title for pid N” via Accessibility. Needed when disk has no row (Safari) or when you want the **window** title after skipping the Open/Save dialog. Not required for the Chrome+Gmail Session path.

### logSuffix

Single formatter for every UPLOAD/DOWNLOAD/HOLD/SCAN line. If title and URL are both missing, it returns `""`. Callers must not print “tab lookup failed”.

### PoC vs product

| Now (this repo) | Later (product) |
| --- | --- |
| `sudo` CLI, SIP off, ad-hoc ES sign | System extension, Apple entitlement |
| Simulated 17s scanner | Real policy HTTP API |
| File events only | File + Network Extension correlation |
| Optional LaunchAgent helper | Helper (or XPC) bundled with the app |

---

## 6. What this project does **not** do

- Chrome extension, TLS intercept, or Network Extension
- Read message contents (WhatsApp E2E, HTTPS bodies)
- Guarantee the Session tab is the window behind a file picker (that is the helper’s job)
- Require `run_tabhelper.sh` for Chrome URL-in-log
- Block AUTH on a hung helper (300ms cap, then omit tab fields)

---

## 7. How to tell what is running

| Question | Check |
| --- | --- |
| Is the ES monitor running? | Activity Monitor / terminal: `MiniFilter` under sudo; you are watching `./run_esmonitor.sh` output |
| Is the tab helper running? | `pgrep -fl MiniFilterTabHelper` and `/tmp/minifilter-tabhelper-$(id -u).sock` |
| Is the helper installed at login? | `launchctl print gui/$(id -u)/com.minifilter.tabhelper` |
| Why do I see a Gmail URL anyway? | Chrome `Session_*` on disk, inside the **root** process |

The script file `run_tabhelper.sh` existing in the repo does not mean it is running.

---

## 8. Source map

| File | Responsibility |
| --- | --- |
| `EndpointSecurityMonitor.swift` | ES client, log lines, wiring |
| `TransferCorrelator.swift` | OPEN/CLONE/WRITE → one UPLOAD/DOWNLOAD |
| `UploadGate.swift` | AUTH retain, deadline math, when to hold |
| `FileScanner.swift` | Simulated policy delay + verdict |
| `ProcessHold.swift` | `thread_suspend` / SIGSTOP + watchdog |
| `VerdictCache.swift` | deny forever / allow 2s |
| `FileClassifier.swift` | extensions, user source vs container |
| `BrowserTab.swift` | catalog, merge, logSuffix, live vs disk |
| `ChromiumSession.swift` | parse Chrome `Session_*` |
| `TabHelper.swift` | Unix socket client + server |
| `MiniFilterTabHelper/main.swift` | user executable |
| `packaging/EndpointSecurity.entitlements` | ES entitlement for ad-hoc sign |
| `packaging/TabHelper-TCC.md` | which TCC boxes to tick on the helper |

---

## 9. One-sentence summary

MiniFilter is a root Endpoint Security PoC that sees file uploads/downloads as they happen, can freeze that syscall while a scan runs, and attaches a browser tab when Chrome’s on-disk session (or an optional user helper) can name the page — without reading the network and without blocking the kernel AUTH reply on UI APIs that root cannot use.
