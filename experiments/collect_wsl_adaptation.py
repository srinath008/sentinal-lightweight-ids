"""Bounded host-adaptation sessions; aggregate features only, no command/path logs.

Run as root on the installed test host. Workloads run as its ordinary user and
touch temporary synthetic files or their own loopback listener only.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0,'/opt/sentinel')
from inference import streaming
from feature_engineering.events import FEATURES

WORKLOAD=r'''
import os, socket, subprocess, sys, tempfile, time
from pathlib import Path
kind=sys.argv[1]; end=time.monotonic()+float(sys.argv[2])
with tempfile.TemporaryDirectory(prefix='sentinel-adapt-') as folder:
    files=[Path(folder)/('synthetic-%03d.txt'%i) for i in range(100)]
    for f in files: f.write_text('Synthetic Sentinel workload; no private information.\n')
    with socket.socket() as server:
        server.bind(('127.0.0.1',0)); server.listen(); port=server.getsockname()[1]
        tick=0
        while time.monotonic()<end:
            tick+=1
            if kind=='benign':
                for f in files[:10]: f.read_bytes()
                if tick%10==0:
                    commands=[['/usr/bin/true'],['/usr/bin/uname','-r'],['/usr/bin/date','+%s'],
                              ['/usr/bin/id'],['/usr/bin/df','-h','/'],['/usr/bin/ps','-eo','comm']]
                    for command in commands:
                        subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
                with socket.create_connection(('127.0.0.1',port)):
                    connection,_=server.accept(); connection.close()
                time.sleep(.2)
            elif kind=='probe_tcp_burst':
                for _ in range(50):
                    with socket.create_connection(('127.0.0.1',port)):
                        connection,_=server.accept(); connection.close()
                time.sleep(.05)
            elif kind=='probe_exec_burst':
                for _ in range(10): subprocess.run(['/usr/bin/true'],check=True)
                time.sleep(.05)
            elif kind=='probe_file_burst':
                for f in files:
                    f.read_bytes()
                    try: Path(str(f)+'.absent').read_bytes()
                    except FileNotFoundError: pass
                time.sleep(.05)
            else: raise ValueError(kind)
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=120)
    parser.add_argument('--probe-seconds',type=int,default=60)
    args=parser.parse_args()
    if os.geteuid()!=0: raise SystemExit('Collectors require administrator access')
    if args.output.exists(): raise SystemExit('Use a new output folder; existing results are preserved')
    args.output.mkdir(parents=True)
    plan=[(part,kind,args.seconds) for part in ('train','validation','test') for kind in ('idle','benign')]
    plan += [('test',kind,args.probe_seconds) for kind in ('probe_tcp_burst','probe_exec_burst','probe_file_burst')]
    manifest=dict(protocol='Separate sequential training, validation and test sessions; frozen plan. Benign synthetic tasks and bounded stress probes, not malware.',
        expected_seconds=sum(x[2] for x in plan),plan=plan,status='running',sessions=[])
    app=None
    try:
        app=subprocess.Popen(['runuser','-u','srinath','--','/usr/local/bin/sentinel','--port','4189'],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
        time.sleep(5)
        if app.poll() is not None: raise RuntimeError('Native diagnostic app could not start')
        for index,(partition,kind,duration) in enumerate(plan):
            sid=f'wsl_{partition}_{kind}_{index}'
            events=[]; failures=[]; worker=None
            def workload():
                try:
                    time.sleep(2)
                    result=subprocess.run(['runuser','-u','srinath','--','/usr/bin/python3','-c',WORKLOAD,kind,str(duration-4)],
                        stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,timeout=duration+5)
                    if result.returncode: failures.append(result.stderr[-1000:])
                except Exception as exc: failures.append(str(exc))
            def emit(event):
                if event['type']=='window':
                    row={key:event[key] for key in ['window_index','window_start',*FEATURES,'n_open_raw','n_unique_paths_raw']}
                    row.update(session_id=sid,partition=partition,workload=kind,
                               phase='baseline' if kind in ('idle','benign') else kind)
                    events.append(row)
                elif event['type'] in ('monitor_stopped','collector_stderr'):
                    events.append(event)
            original=streaming.emit; streaming.emit=emit
            if kind!='idle':
                worker=threading.Thread(target=workload);worker.start()
            try:
                streaming.run(argparse.Namespace(bundle=Path('/opt/sentinel/models/output/improved/detector_bundle.joblib'),
                    tools_dir=Path('/opt/sentinel/collectors'),duration=duration,consecutive=2,cooldown=60,grace=.25))
            finally:
                streaming.emit=original
                if worker: worker.join(timeout=10)
                (args.output/f'{sid}.json').write_text(json.dumps(events,indent=2))
            health=[event for event in events if event.get('type')=='monitor_stopped']
            if failures or not health or any(health[-1][key] for key in ('malformed','late','stderr_lines')):
                raise RuntimeError(f'Invalid session {sid}: {failures} {health}')
            record=dict(session_id=sid,partition=partition,workload=kind,
                        complete_windows=health[-1]['complete_windows'],health=health[-1])
            manifest['sessions'].append(record)
            (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2))
            print(json.dumps(record),flush=True)
        manifest['status']='complete'
    except BaseException as exc:
        manifest.update(status='incomplete',error=str(exc));raise
    finally:
        if app and app.poll() is None:
            os.killpg(app.pid,signal.SIGTERM)
            try: app.wait(timeout=5)
            except subprocess.TimeoutExpired: os.killpg(app.pid,signal.SIGKILL);app.wait()
        (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2))


if __name__=='__main__': main()
