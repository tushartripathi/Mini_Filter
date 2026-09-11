#!/bin/bash
# Builds and runs the user-level tab helper (no sudo).
# Grant Accessibility to THIS binary, not to sudo MiniFilter.
# See packaging/TabHelper-TCC.md.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Compiling MiniFilterTabHelper (release)"
swift build -c release --product MiniFilterTabHelper
BIN="$(swift build -c release --show-bin-path)/MiniFilterTabHelper"

if [[ "${1:-}" == "--install" ]]; then
    DEST="$HOME/Library/Application Support/MiniFilter"
    AGENT_DIR="$HOME/Library/LaunchAgents"
    mkdir -p "$DEST" "$AGENT_DIR"
    HELPER="$DEST/MiniFilterTabHelper"
    cp "$BIN" "$HELPER"
    chmod 755 "$HELPER"
    codesign --force --sign - --identifier com.minifilter.tabhelper "$HELPER" 2>/dev/null || true

    PLIST="$AGENT_DIR/com.minifilter.tabhelper.plist"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.minifilter.tabhelper</string>
    <key>ProgramArguments</key>
    <array>
        <string>${HELPER}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>StandardOutPath</key>
    <string>/tmp/minifilter-tabhelper.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/minifilter-tabhelper.log</string>
</dict>
</plist>
EOF

    UID_NUM="$(id -u)"
    launchctl bootout "gui/${UID_NUM}/com.minifilter.tabhelper" 2>/dev/null || true
    launchctl bootstrap "gui/${UID_NUM}" "$PLIST"
    echo ""
    echo "Installed LaunchAgent: $PLIST"
    echo "Helper binary:         $HELPER"
    echo "Grant TCC to that helper binary (packaging/TabHelper-TCC.md)."
    exit 0
fi

echo ""
echo "Binary: $BIN"
echo "Grant Accessibility to this binary (Privacy & Security → Accessibility)."
echo "See packaging/TabHelper-TCC.md"
echo ""
exec "$BIN"
