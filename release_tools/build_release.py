"""Create a small, explicit-allowlist Linux source/runtime preview package."""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    import pandas as pd
    selected = pd.read_parquet(ROOT / 'models/output/improved/reserved_test_scores.parquet')
    original = pd.read_parquet(ROOT / 'feature_engineering/output/features_window5s_v2.parquet')
    frame = selected[['session_id', 'window_index']].merge(original, on=['session_id', 'window_index'],
                                                          how='left', validate='one_to_one')
    # Retain only original feature inputs, never precomputed predictions.
    from feature_engineering.events import FEATURES
    columns = ['session_id', 'window_index', 'window_start', 'phase', *FEATURES,
               'n_open_raw', 'n_unique_paths_raw']
    if frame[FEATURES].isna().any().any():
        raise ValueError('Missing replay features')
    frame = frame[[c for c in columns if c in frame.columns]].sort_values(['session_id', 'window_index'])
    replay = ROOT / 'desktop/replay.jsonl'
    replay.write_text('\n'.join(json.dumps(row) for row in frame.to_dict('records')) + '\n', encoding='utf-8')
    versions = {name: importlib.metadata.version(name) for name in ('numpy', 'pandas', 'scikit-learn', 'joblib')}
    # Model deserialization is version-sensitive. Pin the actual build runtime.
    (ROOT / 'release_tools/requirements-desktop.txt').write_text('\n'.join(f'{k}=={v}' for k, v in versions.items()) + '\npywebview>=5,<7\n', encoding='utf-8')
    destination = ROOT / 'landing/dist/downloads'
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / 'sentinel-0.1.0-linux-x86_64.tar.gz'
    files = []
    for directory in ('desktop', 'release_tools'):
        files.extend(p for p in (ROOT / directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts
                     and (p.suffix in ('.py', '.html', '.css', '.js', '.svg', '.txt', '.sh', '.desktop') or p.name in ('sentinel', 'sentinel-collector', 'replay.jsonl'))
                     and 'output' not in p.relative_to(ROOT / directory).parts
                     and 'tests' not in p.relative_to(ROOT / directory).parts)
    files.extend(ROOT / p for p in ('inference/detector.py', 'inference/streaming.py',
                                   'inference/evidence.py',
                                   'inference/profile_union.py',
                                   'feature_engineering/events.py', 'feature_engineering/model_features.py',
                                   'models/output/improved/detector_bundle.joblib', 'docs/APP_INSTALL.md'))
    # No raw logs, private documents, source dataset, credentials or other models.
    with tarfile.open(archive, 'w:gz') as output:
        for path in sorted(set(files)):
            relative = Path('INSTALL.md') if path.name == 'APP_INSTALL.md' else path.relative_to(ROOT)
            info = output.gettarinfo(str(path), arcname=str(Path('sentinel-0.1.0') / relative))
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = 0
            if path.suffix == '.sh' or path.name in ('sentinel', 'sentinel-collector'):
                info.mode = 0o755
            else:
                info.mode = 0o644
            with path.open('rb') as stream:
                output.addfile(info, stream)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (destination / 'SHA256SUMS.txt').write_text(checksum + '  ' + archive.name + '\n')
    manifest = dict(version='0.1.0', filename=archive.name, bytes=archive.stat().st_size, sha256=checksum,
                    model_sha256=hashlib.sha256((ROOT / 'models/output/improved/detector_bundle.joblib').read_bytes()).hexdigest(),
                    replay_windows=len(frame), runtime=versions,
                    status='research-preview-linux-installation-unverified')
    (destination / 'release.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
