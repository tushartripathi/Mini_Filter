# WhatsApp Transfer Monitor

A native macOS (SwiftUI) app that detects and logs files transferred through
**WhatsApp Desktop**, with a Start/Stop button and a live event log. Built for
data-loss-prevention auditing on your own machine.

## What it can and cannot see

WhatsApp is end-to-end encrypted, so no external tool can read the *contents* of
a transferred file, and network traffic alone reveals nothing but byte counts.
This app therefore combines three independent local sources:

| Source | Gives you | Limitation |
| --- | --- | --- |
| `ChatStorage.sqlite` | Direction (sent/received), exact byte size, media type, chat/contact name, timestamp | Original filenames are almost never stored |
| FSEvents on WhatsApp's temp dirs | The **original filename** of outgoing files | Only visible while the upload is in flight |
| `nettop` per-process counters | Bytes actually sent by WhatsApp | Volume only, no filenames |

The engine correlates a staged filename with the matching database row (by size
and time) so a single upload shows up as one row with full detail.

### Which files get reported

Only files a person would recognise as their own are logged. WhatsApp constantly
writes internal artefacts — `.dat` blobs, `.enc` payloads, `.thumb` previews,
caches and database journals — so filtering uses an **allowlist** of extensions
rather than trying to block noise as it appears:

| Category | Extensions |
| --- | --- |
| Images | jpg, jpeg, png, gif, heic, heif, webp, bmp, tiff, svg, avif |
| Video | mp4, mov, m4v, avi, mkv, webm, 3gp, mpg, wmv, flv |
| Audio | mp3, m4a, aac, wav, opus, ogg, flac, aiff, amr |
| Documents | pdf, doc(x), xls(x), ppt(x), txt, md, csv, rtf, odt, ods, odp, pages, numbers, key, epub, json, xml, html, vcf, ics |
| Archives | zip, rar, 7z, tar, gz, dmg, iso |

Edit `Core/FileClassifier.swift` to adjust the lists.

### Known accuracy notes

- **Filenames for received files are not recorded by WhatsApp.** Incoming rows
  show type, size, and sender, and the display name reads
  `(no filename recorded)`.
- **Filenames for sent files are best-effort.** They are captured only if the
  app is running when the send happens. Start it before you send.
- Size, direction, type, timestamp, and chat name are reliable for both
  directions.

## Requirements

- macOS 13 or later
- Xcode command line tools (Swift 5.9+)
- WhatsApp Desktop installed in `/Applications`
- **Full Disk Access** — WhatsApp's database lives in a protected container

## Build

```bash
./build_app.sh release
open "build/WhatsApp Transfer Monitor.app"
```

## Grant Full Disk Access

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Click **+** and select `build/WhatsApp Transfer Monitor.app`
3. Quit and relaunch the app

The app shows an orange banner with an **Open Settings** shortcut until access is
granted. Because the bundle is ad-hoc signed, re-running `build_app.sh` keeps the
same identity, so you only need to grant this once — but macOS may ask again if
you move the bundle.

## Using it

Press **Start**. Send or receive a file in WhatsApp and it appears in the table
within about two seconds. Columns show time, direction (Upload or Download),
media type, filename, size, chat, **full path on disk**, which source produced
the row, and raw detail.

The **Path** column shows where the file actually lives. Outgoing files resolve
to WhatsApp's staging directory while the upload is in flight; incoming files
resolve into the media store at
`~/Library/Group Containers/…WhatsApp.shared/Message/Media/<chat-jid>/…`. Rows
read `not on disk` when WhatsApp kept no local copy, which is common for media
it streams on demand.

Footer controls:

- **All / Uploads / Downloads** — filter by transfer direction
- **Include last 24h on start** — prefill with the previous day instead of
  starting empty (applies on the next Start)
- **Filter** — free-text search across filename, chat, type, path, and detail
- **Export CSV** — save the current view
- **Reveal Logs** — open the persistent log folder

## Upload gate (scan before sending)

Turn on **Scan before upload** in the header. When you select a file to send in
WhatsApp, the app:

1. Freezes WhatsApp immediately with `SIGSTOP` — nothing can be transmitted
2. Sends the file to your scanning API as `multipart/form-data`
3. Applies the verdict: **HTTP 200 allows**, any other status **blocks**
4. Resumes WhatsApp, or quarantines the file if blocked

A dialog shows the filename, size, path, a live elapsed counter, and the
server's response message. **Allow now** and **Block now** are manual overrides
if you don't want to wait.

### Configuration

Click the gear beside the toggle:

- **Policy server endpoint** — leave empty to use the built-in simulated
  scanner, which waits and then approves. This lets you exercise the whole flow
  before your API exists.
- **Simulated delay** — how long the fake scanner takes (shown only when no
  endpoint is set)
- **Skip files larger than** — default 50 MB; oversized files skip the scan and
  take the failure policy

Timeout is 10 seconds.

### Failure policy: fail open

If the server errors, times out, or is unreachable, the upload is **allowed** and
the reason is written to the log. This keeps an outage from blocking your work,
but it does mean anyone who can break the scanner can bypass the gate. To
reverse this, set `allowOnScanFailure = false` in `MonitorEngine`.

### Why it works this way

macOS gives a normal app no way to intercept and hold another app's network
traffic. That requires a Network Extension content filter (see
[Endpoint Security PoC](#endpoint-security-poc-system-wide-file-access) for the
production path). Without it, the only mechanism available here is suspending
the process: a stopped process cannot execute, so it cannot transmit.

The gate fires at **file-selection time**, not send time. This is deliberate —
selection reliably precedes any network transmission, whereas by the time a
message record exists the upload is often already in flight. The trade-off is
that the whole app freezes, not just the transfer.

### Blocking

A block copies the staged file into `~/Library/Logs/MiniFilter/Quarantine/` and
removes the original, so WhatsApp cannot read it. The copy is kept so the block
is auditable. Expect WhatsApp to report a send error — that is the intended
outcome of a block.

### Testing the gate

A mock endpoint implementing the contract is included:

```bash
python3 tools/mock_scan_server.py            # always allows (HTTP 200)
python3 tools/mock_scan_server.py --reject   # always blocks (HTTP 403)
python3 tools/mock_scan_server.py --hang     # never responds, to test the timeout
```

Then drive the whole gate headlessly, which stages a file, freezes WhatsApp and
reports what happened:

```bash
BIN="$(swift build -c release --show-bin-path)/MiniFilter"

"$BIN" --gatetest 6                                    # simulated scanner
"$BIN" --gatetest 6 http://127.0.0.1:8099/scan          # real endpoint
```

### Safety

Leaving WhatsApp permanently frozen is the one serious risk, so there are four
independent safeguards:

1. An independent 10s deadline settles the verdict even if the scanner never
   calls back.
2. An in-process hard cap (scan timeout + 10s, ceiling 120s).
3. An `atexit` handler resuming it on normal termination.
4. A **detached shell watchdog** that outlives this app entirely and issues
   `SIGCONT` even if the app is `SIGKILL`ed or panics.

All four are verified by `--holdtest` and `--watchdogtest`.

## Logs

Every event is appended as newline-delimited JSON to:

```
~/Library/Logs/MiniFilter/whatsapp-transfers-YYYY-MM-DD.jsonl
```

JSONL is used so the log survives a crash and can be tailed or ingested by other
tooling without a parsing step.

## Verification without the GUI

```bash
BIN="$(swift build -c release --show-bin-path)/MiniFilter"

# Check access, run the query, summarise the last 24h of transfers
"$BIN" --selftest

# Print live filesystem observations for 30 seconds
"$BIN" --watchtest 30

# Suspend WhatsApp for 5s and confirm it resumes (prints process state)
"$BIN" --holdtest 5

# Suspend WhatsApp then exit without resuming, to prove the watchdog recovers it
"$BIN" --watchdogtest

# Endpoint Security file-access monitor (requires sudo, FDA, ES entitlement)
./run_esmonitor.sh --seconds 30 --process WhatsApp
```

`--selftest` is the fastest way to confirm Full Disk Access is working.

## How it works

- `Core/WhatsAppPaths.swift` — the container paths that were reverse-engineered
- `Core/ChatStorageReader.swift` — WAL-safe snapshot reads of the Core Data store,
  incremental by message primary key so each transfer is reported exactly once
- `Core/FileClassifier.swift` — the user-facing-file allowlist, plus recovery of a
  chat JID from a media path
- `Core/StagingWatcher.swift` — FSEvents stream, stats files the instant they
  appear because they are deleted seconds later
- `Core/NetworkSampler.swift` — parses `nettop` byte counters
- `Core/TransferProbe.swift` — serialises the two blocking sources off the main thread
- `Core/MonitorEngine.swift` — correlation, session totals, logging
- `Core/EndpointSecurityMonitor.swift` — `--esmonitor`: system-wide file OPEN/CLONE/COPYFILE via Endpoint Security
- `UI/ContentView.swift` — Start/Stop, live table, permission banner, export

### Why snapshot the database

The live store is in WAL mode and held open by WhatsApp. Opening it in place
needs write access to the `-shm` file, and opening it `immutable=1` hides
everything still in the `-wal` — which is exactly where new messages are. So the
main database is copied only when it changes, while the small `-wal`/`-shm` pair
is refreshed on every poll.

## Endpoint Security PoC (system-wide file access)

The WhatsApp database path above is a user-space workaround. Production DLP on
Mac should not scrape another app's files. It should get a kernel-mediated
**event when any process opens, copies or writes a file**, then (separately)
see the network flow.

That is two Apple frameworks, not one:

| Layer | Framework | What it sees | What it does not see |
| --- | --- | --- | --- |
| File | **Endpoint Security** | Process X opened / cloned / created `secret.pdf` | HTTPS bodies, "this was an upload" |
| Network | **Network Extension** (`NEFilterDataProvider`) | Process X connected to host Y and sent N bytes | Which file those bytes came from |

Correlate them: a read of a user file followed by a connection from the same
process is an upload; a connection followed by a create/write is a download.
That covers WhatsApp, browsers, Slack, `curl`, and everything else — which is
the production goal.

This repo now includes the **file half** as a notify-only PoC.

### Run it

```bash
./run_esmonitor.sh
./run_esmonitor.sh --process WhatsApp
./run_esmonitor.sh --seconds 60 --json
```

`--process` may be repeated. Default is every process, but only
user-facing extensions (the same allowlist as the WhatsApp monitor).
`--all-files` drops that filter.

Send a document from WhatsApp (or attach one in Mail, or open one in Chrome).
You should see an `OPEN` line for the original path **before** WhatsApp copies
it into its container — that is the trigger the database approach never had.

JSONL is also written to `~/Library/Logs/MiniFilter/es-access-YYYY-MM-DD.jsonl`.

### What you need for the PoC to actually subscribe

`es_new_client` refuses to start unless all of these are true:

1. **Root** — `run_esmonitor.sh` uses `sudo`
2. **Full Disk Access** for the signed binary
3. **The ES entitlement** `com.apple.developer.endpoint-security.client`

That entitlement is **restricted**. With SIP enabled, an ad-hoc signature is
ignored and you get `NOT_ENTITLED`. For a local PoC, disable SIP, then run the
script (it ad-hoc signs with `packaging/EndpointSecurity.entitlements`). For
anything you would ship, request the entitlement from Apple and run the client
inside a **system extension**, not a `sudo` CLI.

If `es_new_client` fails, the process prints which of the three checks failed.

### What this PoC does not do yet

- **No AUTH events.** `AUTH_OPEN` can deny the file open (block the upload at
  source). A missed reply hangs the target app, so it is left for the system
  extension, which must reply on every event.
- **No Network Extension.** File `OPEN` with `inferred=possible-upload-source`
  is a guess. Confirmed uploads/downloads need the content filter.
- **No GUI.** ES clients run as root; the SwiftUI app stays unprivileged. The
  production shape is: system extension (ES + NE) talking over XPC to this UI.

### Apple requests (production)

- Endpoint Security: [System Extension entitlement request](https://developer.apple.com/contact/request/system-extension/)
- Network filter: [Network Extension entitlement request](https://developer.apple.com/contact/request/network-extension/)

Expect a paid Developer Program account, a description of the DLP product, and
a system-extension installer. The CLI in this repo is only to prove the event
you wanted exists.

## Scope

The GUI still monitors **WhatsApp Desktop** via ChatStorage + FSEvents. The
`--esmonitor` path is process-agnostic and is the start of the production
design. WhatsApp Web in a browser is invisible to the GUI; Endpoint Security
plus a Network Extension is how that (and every other app) gets covered.
