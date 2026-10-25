"""Bounded, harmless diagnostics for Srinath's WSL install. Run as root.

Writes diagnostic data only; does not train or replace the installed model.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, '/opt/sentinel')
from inference import streaming

WORKLOAD = r'''
import json, os, socket, subprocess, tempfile, time
from pathlib import Path
with tempfile.TemporaryDirectory(prefix='sentinel-safe-check-') as folder:
    target=Path(folder)/'known-clean.txt'
    target.write_text('Harmless Sentinel verification.\n')
    for _ in range(20):
        subprocess.run(['/usr/bin/printf','sentinel-collector-check'], stdout=subprocess.DEVNULL, check=True)
        time.sleep(.1)
    for _ in range(100):
        target.read_bytes()
        try: (Path(folder)/'deliberately-missing.txt').read_bytes()
        except FileNotFoundError: pass
        time.sleep(.01)
    with socket.socket() as server:
        server.bind(('127.0.0.1',0)); server.listen()
        port=server.getsockname()[1]
        for _ in range(100):
            with socket.create_connection(('127.0.0.1',port)) as client:
                connection,_=server.accept(); connection.close()
            time.sleep(.01)
    print(json.dumps(dict(pid=os.getpid(),successful_execs=20,file_reads=100,
                         missing_file_attempts=100,loopback_connections=100,port=port)),flush=True)
'''


def measure(label, seconds, controlled=False):
    events=[]
    counts=Counter()
    process_counts=Counter()
    samples={source:[] for source in streaming.SOURCES}
    original_parse=streaming.parse_event
    original_emit=streaming.emit
    workload_result={}
    worker=None
    malformed=[]
    error=None
    markers=Counter()
    tcp_ports=Counter()

    def parse(source, raw):
        try:
            event=original_parse(source, raw)
        except ValueError:
            if len(malformed)<10:
                malformed.append(dict(source=source,row=raw.rstrip()[:300]))
            raise
        if event:
            if source=='tcpconnect' and event['daddr']=='127.0.0.1':
                tcp_ports[event['dport']]+=1
            if source=='opensnoop' and 'sentinel-safe-check-' in event['path']:
                if event['path'].endswith('/known-clean.txt') and event['err']==0:
                    markers['clean_file_opens']+=1
                if event['path'].endswith('/deliberately-missing.txt') and event['err']!=0:
                    markers['expected_missing_file_errors']+=1
            counts[source]+=1
            process_counts[(source,event['pid'],event.get('comm',event.get('pcomm','')))]+=1
            if len(samples[source])<12:
                # No command arguments are retained in the diagnostic.
                samples[source].append({key:value for key,value in event.items() if key!='args'})
        return event

    def workload():
        time.sleep(3)
        result=subprocess.run(['runuser','-u','srinath','--','/usr/bin/python3','-c',WORKLOAD],
                              capture_output=True,text=True,timeout=15)
        workload_result.update(returncode=result.returncode,stderr=result.stderr[-1000:])
        if result.returncode==0:
            workload_result.update(json.loads(result.stdout))

    def emit(event):
        events.append(event)

    streaming.parse_event=parse
    streaming.emit=emit
    try:
        if controlled:
            worker=threading.Thread(target=workload)
            worker.start()
        streaming.run(argparse.Namespace(bundle=Path('/opt/sentinel/models/output/improved/detector_bundle.joblib'),
            tools_dir=Path('/opt/sentinel/collectors'),duration=seconds,consecutive=2,cooldown=60,grace=.25))
    except Exception as exc:
        error=str(exc)
    finally:
        if worker: worker.join(timeout=20)
        streaming.parse_event=original_parse
        streaming.emit=original_emit
    windows=[event for event in events if event['type']=='window']
    result=dict(label=label,requested_seconds=seconds,windows=windows,
        health=[event for event in events if event['type']=='monitor_stopped'],
        collector_messages=[event for event in events if event['type']=='collector_stderr'],
        event_counts=dict(counts),raw_samples=samples,
        top_processes=[dict(source=source,pid=pid,name=name,events=count)
                       for (source,pid,name),count in process_counts.most_common(15)],
        workload=workload_result,error=error,malformed_samples=malformed,marker_counts=dict(markers))
    if controlled and workload_result.get('pid'):
        pid=workload_result['pid']
        result['controlled_observed']=dict(
            printf_execs=sum(count for (source,_,name),count in process_counts.items()
                             if source=='execsnoop' and name=='printf'),
            clean_file_opens=markers['clean_file_opens'],
            expected_missing_file_errors=markers['expected_missing_file_errors'],
            controlled_loopback_connections=tcp_ports[workload_result['port']])
        result['pid_note']='Workload PID is from procfs; collector PID may be in the kernel PID namespace on WSL. Match unique test paths and destination port instead.'
    print(json.dumps(dict(phase=label,complete_windows=len(windows),flagged=sum(w['anomaly'] for w in windows),
                          events=dict(counts),controlled_observed=result.get('controlled_observed'),
                          error=error,malformed_samples=malformed)),flush=True)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controlled-only',action='store_true')
    args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Collectors require administrator access')
    phases=[]
    app=None
    try:
        if args.controlled_only:
            phases.append(measure('controlled_collector_probe',22,controlled=True))
            return
        phases.append(measure('app_closed_idle',35))
        app=subprocess.Popen(['runuser','-u','srinath','--','/usr/local/bin/sentinel','--port','4188'],
                             stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        time.sleep(5)
        if app.poll() is not None: raise RuntimeError('Diagnostic native app did not start')
        phases.append(measure('app_open_idle',35))
        phases.append(measure('app_open_controlled_benign',22,controlled=True))
        phases.append(measure('app_open_idle_holdout',35))
    finally:
        if app and app.poll() is None:
            os.killpg(app.pid,signal.SIGTERM)
            try: app.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(app.pid,signal.SIGKILL); app.wait()
        args.output.write_text(json.dumps(dict(phases=phases,
            limitation='Short sequential diagnostic runs on one WSL host, not a randomized benchmark or independent malware test. Controlled activity is benign, not an attack.'),indent=2))


if __name__=='__main__': main()
