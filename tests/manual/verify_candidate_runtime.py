"""Check a trusted candidate's Linux scores against the saved Windows results."""
import argparse
import json
from pathlib import Path
import sys
import time
import resource

sys.path.insert(0,'/opt/sentinel')
from inference.detector import Detector


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    parser.add_argument('--sessions',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    expected=json.loads(args.report.read_text())
    detector=Detector(args.bundle)
    truth_positive=truth_negative=false_positive=false_negative=0
    for line in Path('/opt/sentinel/desktop/replay.jsonl').read_text().splitlines():
        row=json.loads(line);flag=detector.score(row)['anomaly'];attack=row['phase'].startswith('attack_')
        truth_positive+=bool(flag and attack);false_negative+=bool(not flag and attack)
        false_positive+=bool(flag and not attack);truth_negative+=bool(not flag and not attack)
    observed=dict(true_positives=truth_positive,false_negatives=false_negative,
                  false_positives=false_positive,true_negatives=truth_negative)
    for key,value in observed.items(): assert value==expected['test']['historical'][key],(key,value,expected['test']['historical'][key])
    counts={};example=None
    manifest=json.loads((args.sessions/'manifest.json').read_text())
    for session in manifest['sessions']:
        if session['partition']!='test':continue
        captured=json.loads((args.sessions/(session['session_id']+'.json')).read_text())
        windows=[row for row in captured if 'window_index' in row][2:-2]
        counts[session['workload']]=dict(windows=len(windows),flagged=sum(detector.score(row)['anomaly'] for row in windows))
        example=windows[0]
        expected_counts=expected['test']['wsl'][session['workload']]
        assert counts[session['workload']]['flagged']==expected_counts['flagged'],(counts,expected_counts)
    timings=[]
    for _ in range(100):
        start=time.perf_counter();detector.score(example);timings.append((time.perf_counter()-start)*1000)
    result=dict(status='passed',name=detector.bundle['primary_name'],historical=observed,wsl=counts,
        prediction_median_ms=sorted(timings)[50],prediction_p95_ms=sorted(timings)[95],
        process_peak_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,
        note='Standalone Python inference process RSS includes imported dependencies; excludes GUI, collectors and ClamAV. Scores match the saved Windows evaluation counts.')
    args.output.write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))


if __name__=='__main__':main()
