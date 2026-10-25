#!/bin/bash
# Harmless demo workload for Sentinel live mode (run in Ubuntu, as a normal user).
# Starts many short processes, opens many files and makes loopback-only HTTP requests for ~25 s.
# Nothing is modified and nothing leaves this machine.
end=$((SECONDS+25))
python3 -m http.server 38999 --bind 127.0.0.1 >/dev/null 2>&1 & server=$!
trap 'kill $server 2>/dev/null' EXIT
sleep 1
while [ $SECONDS -lt $end ]; do
  for i in $(seq 1 40); do /bin/true; done
  find /usr/lib -maxdepth 3 -type f -exec head -c1 {} \; >/dev/null 2>&1
  for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:38999/; done
done
echo "burst finished"
