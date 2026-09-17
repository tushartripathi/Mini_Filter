#!/bin/bash
# Builds, ad-hoc signs with the Endpoint Security entitlement, and runs the
# file-access monitor as root.
#
# Foreground (current terminal):
#   ./run_esmonitor.sh [--process NAME] [--verbose] ...
#
# System LaunchDaemon (survives logout, restarts on crash):
#   ./run_esmonitor.sh --install [--process NAME] ...
#   ./run_esmonitor.sh --uninstall
#
# Local PoC: SIP must be disabled or Apple ignores this restricted entitlement.
# Production: a Developer ID + Apple-granted ES entitlement, shipped as a
# system extension — not this script.
set -euo pipefail

cd "$(dirname "$0")"

LABEL="com.minifilter.esmonitor"
DEST_DIR="/Library/Application Support/MiniFilter"
DEST_BIN="$DEST_DIR/MiniFilter"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SYSLOG_DIR="/Library/Logs/MiniFilter"
BIN=""

usage_hint() {
    echo "If es_new_client fails with NOT_PERMITTED, grant Full Disk Access to:"
    echo "  $1"
}

build_and_sign() {
    echo "==> Compiling (release)"
    swift build -c release
    BIN="$(swift build -c release --show-bin-path)/MiniFilter"

    echo "==> Signing with Endpoint Security entitlement"
    codesign --force --sign - \
        --entitlements packaging/EndpointSecurity.entitlements \
        --identifier com.minifilter.esmonitor \
        "$BIN"
}

console_user() {
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        echo "$SUDO_USER"
        return
    fi
    stat -f '%Su' /dev/console 2>/dev/null || id -un
}

do_uninstall() {
    echo "==> Unloading LaunchDaemon ${LABEL}"
    sudo launchctl bootout "system/${LABEL}" 2>/dev/null || true
    sudo rm -f "$PLIST"
    echo "Left binary in place: $DEST_BIN"
    echo "Remove it with: sudo rm -rf \"$DEST_DIR\""
}

do_install() {
    local extra_args=("$@")
    for a in "${extra_args[@]+"${extra_args[@]}"}"; do
        if [[ "$a" == "--seconds" ]]; then
            echo "error: --seconds exits the monitor; do not use it on a LaunchDaemon" >&2
            exit 1
        fi
    done

    build_and_sign
    local user home
    user="$(console_user)"
    home="$(dscl . -read "/Users/${user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    if [[ -z "$home" ]]; then
        home="/Users/${user}"
    fi

    echo "==> Installing to ${DEST_BIN} (user for logs/Chrome profile: ${user})"
    sudo mkdir -p "$DEST_DIR" "$SYSLOG_DIR"
    sudo cp "$BIN" "$DEST_BIN"
    sudo chmod 755 "$DEST_BIN"
    sudo codesign --force --sign - \
        --entitlements packaging/EndpointSecurity.entitlements \
        --identifier com.minifilter.esmonitor \
        "$DEST_BIN"

    local tmp
    tmp="$(mktemp)"
    {
        cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${DEST_BIN}</string>
        <string>--esmonitor</string>
EOF
        for a in "${extra_args[@]+"${extra_args[@]}"}"; do
            printf '        <string>%s</string>\n' "$a"
        done
        cat <<EOF
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>${home}</string>
        <key>SUDO_USER</key>
        <string>${user}</string>
    </dict>
    <key>StandardOutPath</key>
    <string>${SYSLOG_DIR}/esmonitor.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${SYSLOG_DIR}/esmonitor.stderr.log</string>
</dict>
</plist>
EOF
    } > "$tmp"
    sudo cp "$tmp" "$PLIST"
    sudo chmod 644 "$PLIST"
    rm -f "$tmp"

    sudo launchctl bootout "system/${LABEL}" 2>/dev/null || true
    sudo launchctl bootstrap system "$PLIST"
    sudo launchctl enable "system/${LABEL}" 2>/dev/null || true
    sudo launchctl kickstart -k "system/${LABEL}"

    echo ""
    echo "Installed LaunchDaemon: $PLIST"
    echo "Binary:                 $DEST_BIN"
    echo "Stdout/stderr:          $SYSLOG_DIR/esmonitor.stdout.log"
    echo "JSONL:                  ${home}/Library/Logs/MiniFilter/"
    echo ""
    usage_hint "$DEST_BIN"
    echo "Grant Full Disk Access to that installed binary, then:"
    echo "  sudo launchctl kickstart -k system/${LABEL}"
    echo "Status: sudo launchctl print system/${LABEL}"
    echo "Logs:   sudo tail -f ${SYSLOG_DIR}/esmonitor.stdout.log"
}

cmd="${1:-}"
if [[ "$cmd" == "--install" ]]; then
    shift
    do_install "$@"
    exit 0
fi
if [[ "$cmd" == "--uninstall" ]]; then
    do_uninstall
    exit 0
fi

build_and_sign
echo ""
echo "Binary: $BIN"
usage_hint "$BIN"
echo ""

exec sudo "$BIN" --esmonitor "$@"
