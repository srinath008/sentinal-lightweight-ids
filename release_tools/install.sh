#!/usr/bin/env bash
# User-reviewed installer; no download-and-execute pipeline.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${EUID} -eq 0 ]]; then
  echo 'Run this installer as your ordinary Linux user. It requests sudo for installation.' >&2
  exit 1
fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'This preview installer supports Ubuntu/Debian on Linux x86_64.' >&2
  exit 1
fi
if [[ -e /opt/sentinel ]]; then
  echo 'An installation already exists. Run its uninstall command before reinstalling.' >&2
  exit 1
fi
command -v apt-get >/dev/null || { echo 'An apt-based distribution is required.' >&2; exit 1; }
echo 'Installing Sentinel research preview into /opt/sentinel.'
sudo apt-get update
sudo apt-get install -y python3-venv python3-pip python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-webkit2-4.1 pkexec policykit-1-gnome xterm clamav libnotify-bin notification-daemon
python3 -m venv --system-site-packages .install-venv
.install-venv/bin/python -m pip install -r release_tools/requirements-desktop.txt
# Fail before installing if the bundled model is incompatible with this runtime.
.install-venv/bin/python -c "from inference.detector import Detector; Detector('models/output/improved/detector_bundle.joblib'); print('Model compatibility verified')"
sudo install -d -m 755 /opt/sentinel
for item in desktop inference feature_engineering models release_tools; do
  sudo cp -R -- "$item" /opt/sentinel/
done
sudo cp -R -- .install-venv /opt/sentinel/.venv
# Venv activation files refer to the build directory; launch via the explicit
# interpreter path. No console-script shebang from this venv is used.
sudo install -d -m 755 /opt/sentinel/bin /opt/sentinel/collectors
sudo install -m 755 release_tools/sentinel /opt/sentinel/bin/sentinel
sudo install -m 755 release_tools/sentinel-collector /opt/sentinel/bin/sentinel-collector
sudo chown -R root:root /opt/sentinel
sudo chmod -R go-w /opt/sentinel
sudo ln -s /opt/sentinel/bin/sentinel /usr/local/bin/sentinel
sudo install -m 644 release_tools/sentinel.desktop /usr/share/applications/sentinel.desktop
echo 'Installed. Launch Sentinel from your applications menu, or run: sentinel --browser'
echo 'Replay is available immediately. Live mode needs CO-RE collectors; see INSTALL.md.'
