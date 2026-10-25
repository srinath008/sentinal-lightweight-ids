#!/usr/bin/env bash
set -euo pipefail
if [[ -d /opt/sentinel ]]; then
  echo 'Close Sentinel and stop monitoring before uninstalling.'
  sudo mv -- /opt/sentinel "/opt/sentinel-removed-$(date +%s)"
  sudo rm -f -- /usr/local/bin/sentinel /usr/share/applications/sentinel.desktop
  echo 'Uninstalled. Files were moved to /opt/sentinel-removed-TIMESTAMP for recovery.'
  echo 'Your local history under ~/.local/state/sentinel was preserved.'
fi
