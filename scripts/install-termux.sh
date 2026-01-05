#!/data/data/com.termux/files/usr/bin/bash
#
# PhonePod Installer for Termux
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/JavaScriptSolidServer/JavaScriptSolidServer/gh-pages/scripts/install-termux.sh | bash
#

set -e

echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║         PhonePod Installer            ║"
echo "  ║   Solid + Nostr + Git on your phone   ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""

# Check we're in Termux
if [ ! -d "/data/data/com.termux" ]; then
  echo "✗ This script is for Termux on Android"
  echo "  Install Termux from F-Droid: https://f-droid.org/packages/com.termux/"
  exit 1
fi

echo "→ Installing dependencies..."
pkg update -y
pkg install -y nodejs-lts openssh autossh git

echo "→ Installing PM2 and JSS..."
npm install -g pm2 javascript-solid-server

# Fix PATH for npm global bins
NPM_BIN="$(npm config get prefix)/bin"
if [[ ":$PATH:" != *":$NPM_BIN:"* ]]; then
  echo "export PATH=\"\$PATH:$NPM_BIN\"" >> ~/.bashrc
  export PATH="$PATH:$NPM_BIN"
fi

echo "→ Setting up boot persistence..."
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/start-pod.sh << 'BOOT'
#!/data/data/com.termux/files/usr/bin/bash
# Start PhonePod on boot
termux-wake-lock
export PATH="$PATH:$(npm config get prefix)/bin"
pm2 resurrect
BOOT
chmod +x ~/.termux/boot/start-pod.sh

echo "→ Starting JSS..."
pm2 start jss -- start --port 8080 --nostr --git
pm2 save

# Get local IP
LOCAL_IP=$(ip route get 1 2>/dev/null | awk '{print $7}' | head -1)

echo ""
echo "  ╔═══════════════════════════════════════╗"
echo "  ║         ✓ PhonePod Installed!         ║"
echo "  ╚═══════════════════════════════════════╝"
echo ""
echo "  Local:   http://localhost:8080"
if [ -n "$LOCAL_IP" ]; then
echo "  Network: http://$LOCAL_IP:8080"
fi
echo ""
echo "  Features enabled:"
echo "    • Solid pod (LDP, WAC, WebID)"
echo "    • Nostr relay (wss://localhost:8080/relay)"
echo "    • Git server (git clone http://localhost:8080/)"
echo ""
echo "  Commands:"
echo "    pm2 status      - check status"
echo "    pm2 logs jss    - view logs"
echo "    pm2 restart jss - restart server"
echo ""
echo "  For public access, setup a tunnel:"
echo "    https://github.com/JavaScriptSolidServer/JavaScriptSolidServer/issues/46"
echo ""
echo "  NOTE: Install Termux:Boot from F-Droid for auto-start on reboot"
echo ""
