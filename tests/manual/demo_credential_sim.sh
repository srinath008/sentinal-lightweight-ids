#!/bin/bash
# Simulated credential-access pattern for Sentinel live mode (run in Ubuntu, as a normal user).
# Tries to open /etc/shadow and /etc/sudoers (the kernel refuses, which is fine: the attempt is the signal)
# while generating a burst of activity. File contents are never read or stored.
end=$((SECONDS+14))
while [ $SECONDS -lt $end ]; do
  for i in $(seq 1 25); do cat /etc/shadow /etc/sudoers >/dev/null 2>&1; done
  find /usr/lib -maxdepth 3 -type f -exec head -c1 {} \; >/dev/null 2>&1
done
echo "simulation finished"
