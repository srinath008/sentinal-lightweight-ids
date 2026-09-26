"""
feature_engineering/eda.py
----------------------------
WP-06: Exploratory Sanity Checks

Loads the pre-built feature table and produces:
  1. Summary statistics grouped by phase (printed to stdout)
  2. Phase-distribution bar chart (per session)
  3. Time-series plots of key features over a full session, coloured by phase
  4. Box plots of each feature split by phase (baseline vs attacks)
  5. Correlation heatmap of feature columns

All plots are saved to feature_engineering/output/eda_plots/.
Run this script, review the plots, and confirm they look sensible before
proceeding to model training (WP-07/08) — this is the human checkpoint
described in §3.14 of the handoff document.

Usage:
    python feature_engineering/eda.py

Expected results if pipeline is correct:
  - n_tcp_connect should spike sharply during attack_recon
  - n_open_raw / n_open should spike during attack_privesc and attack_fileaccess
  - n_exec / n_unique_pcomm should be elevated during attack phases
  - Phase boundaries on time-series should visually align with the data
"""

from __future__ import annotations
import sys
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')          # non-interactive backend — saves to file
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

logging.basicConfig(level=logging.INFO, format='%(message)s')
log = logging.getLogger(__name__)

# Add project root to path so we can import our modules
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from feature_engineering.features import load_features, DEFAULT_WINDOW_SECONDS

# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────

OUTPUT_DIR = Path(__file__).parent / 'output' / 'eda_plots'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

PHASE_COLORS = {
    'baseline':          '#2196F3',   # blue
    'attack_recon':      '#FF9800',   # orange
    'attack_privesc':    '#F44336',   # red
    'attack_fileaccess': '#9C27B0',   # purple
    'unlabeled':         '#9E9E9E',   # grey
}
PHASE_ORDER = ['baseline', 'attack_recon', 'attack_privesc', 'attack_fileaccess', 'unlabeled']

FEATURE_COLS = [
    'n_exec', 'n_unique_pcomm',
    'n_open_raw', 'n_unique_paths_raw', 'n_open_errors',
    'n_open', 'n_unique_paths',
    'n_tcp_connect', 'n_unique_daddr',
]

# Features to highlight in time-series (most interpretable ones)
KEY_FEATURES = ['n_exec', 'n_open_raw', 'n_tcp_connect']


# ──────────────────────────────────────────────────────────────────────────────
# 1. Summary statistics by phase
# ──────────────────────────────────────────────────────────────────────────────

def print_phase_stats(ft: pd.DataFrame) -> None:
    print("\n" + "="*70)
    print("FEATURE STATISTICS BY PHASE (combined both sessions)")
    print("="*70)

    # pandas 3.x groupby().describe() returns a flat DataFrame when called
    # on individual columns, or a MultiIndex when called on multiple columns.
    # Use xs() to extract the stats we care about cleanly.
    for feat in FEATURE_COLS:
        desc = ft.groupby('phase')[feat].describe()[['mean', 'std', 'min', '50%', 'max']]
        desc.columns = [f'{feat}_{c}' for c in desc.columns]
        print(f'\n  {feat}:')
        print(desc.round(2).to_string())

    print("\n--- Window counts per phase ---")
    print(ft.groupby(['session_id', 'phase']).size().unstack(fill_value=0).to_string())


# ──────────────────────────────────────────────────────────────────────────────
# 2. Phase distribution bar chart
# ──────────────────────────────────────────────────────────────────────────────

def plot_phase_distribution(ft: pd.DataFrame) -> None:
    sessions = ft['session_id'].unique()
    fig, axes = plt.subplots(1, len(sessions), figsize=(5 * len(sessions), 4), sharey=False)
    if len(sessions) == 1:
        axes = [axes]

    for ax, sess in zip(axes, sessions):
        sub = ft[ft['session_id'] == sess]
        counts = sub['phase'].value_counts().reindex(PHASE_ORDER, fill_value=0)
        bars = ax.bar(
            counts.index, counts.values,
            color=[PHASE_COLORS.get(p, '#888') for p in counts.index],
        )
        ax.set_title(f'Session {sess[-8:]}', fontsize=10)
        ax.set_xlabel('Phase')
        ax.set_ylabel('Windows (5 s each)')
        ax.tick_params(axis='x', rotation=30)
        for bar, v in zip(bars, counts.values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                    str(v), ha='center', va='bottom', fontsize=8)

    fig.suptitle('Window count per phase', fontsize=12, fontweight='bold')
    fig.tight_layout()
    out = OUTPUT_DIR / 'phase_distribution.png'
    fig.savefig(out, dpi=150)
    plt.close(fig)
    log.info('Saved → %s', out)


# ──────────────────────────────────────────────────────────────────────────────
# 3. Time-series plots (key features, coloured by phase)
# ──────────────────────────────────────────────────────────────────────────────

def plot_timeseries(ft: pd.DataFrame) -> None:
    sessions = ft['session_id'].unique()

    for sess in sessions:
        sub = ft[ft['session_id'] == sess].sort_values('window_index').reset_index(drop=True)
        t = sub['window_index']

        fig, axes = plt.subplots(len(KEY_FEATURES), 1,
                                 figsize=(14, 3.5 * len(KEY_FEATURES)), sharex=True)

        for ax, feat in zip(axes, KEY_FEATURES):
            # Plot the feature as a line
            ax.plot(t, sub[feat], color='#555', linewidth=0.6, alpha=0.7)

            # Shade background by phase
            for phase in PHASE_ORDER:
                mask = (sub['phase'] == phase).values
                if not mask.any():
                    continue
                # Draw vertical spans for each contiguous run of this phase
                in_run = False
                run_start = 0
                for i, m in enumerate(mask):
                    if m and not in_run:
                        run_start = t.iloc[i]
                        in_run = True
                    elif not m and in_run:
                        ax.axvspan(run_start, t.iloc[i-1],
                                   color=PHASE_COLORS[phase], alpha=0.15)
                        in_run = False
                if in_run:
                    ax.axvspan(run_start, t.iloc[-1],
                               color=PHASE_COLORS[phase], alpha=0.15)

            ax.set_ylabel(feat, fontsize=9)
            ax.set_yscale('symlog' if feat == 'n_open_raw' else 'linear')
            ax.grid(axis='y', alpha=0.3)

        # Legend
        patches = [mpatches.Patch(color=PHASE_COLORS[p], label=p, alpha=0.5)
                   for p in PHASE_ORDER if p in sub['phase'].values]
        axes[0].legend(handles=patches, loc='upper right', fontsize=8, ncol=2)

        axes[-1].set_xlabel('Window index (5 s each)')
        fig.suptitle(f'Key features over time — session {sess[-8:]}',
                     fontsize=12, fontweight='bold')
        fig.tight_layout()

        out = OUTPUT_DIR / f'timeseries_{sess}.png'
        fig.savefig(out, dpi=150)
        plt.close(fig)
        log.info('Saved → %s', out)


# ──────────────────────────────────────────────────────────────────────────────
# 4. Box plots by phase
# ──────────────────────────────────────────────────────────────────────────────

def plot_boxplots(ft: pd.DataFrame) -> None:
    plot_feats = ['n_exec', 'n_open_raw', 'n_tcp_connect',
                  'n_unique_pcomm', 'n_unique_paths_raw', 'n_unique_daddr']
    phases_present = [p for p in PHASE_ORDER if p in ft['phase'].values and p != 'unlabeled']
    n_feats = len(plot_feats)

    fig, axes = plt.subplots(2, 3, figsize=(15, 8))
    axes = axes.flatten()

    for ax, feat in zip(axes, plot_feats):
        data   = [ft.loc[ft['phase'] == p, feat].values for p in phases_present]
        colors = [PHASE_COLORS[p] for p in phases_present]
        bp = ax.boxplot(data, patch_artist=True, notch=False,
                        medianprops=dict(color='black', linewidth=2))
        for patch, color in zip(bp['boxes'], colors):
            patch.set_facecolor(color)
            patch.set_alpha(0.6)
        ax.set_yscale('symlog' if feat in ('n_open_raw', 'n_unique_paths_raw') else 'linear')
        ax.set_title(feat, fontsize=10, fontweight='bold')
        ax.set_xticks(range(1, len(phases_present) + 1))
        ax.set_xticklabels([p.replace('attack_', '') for p in phases_present],
                           rotation=20, fontsize=8)
        ax.grid(axis='y', alpha=0.3)

    fig.suptitle('Feature distributions by phase (both sessions combined)',
                 fontsize=12, fontweight='bold')
    fig.tight_layout()
    out = OUTPUT_DIR / 'boxplots_by_phase.png'
    fig.savefig(out, dpi=150)
    plt.close(fig)
    log.info('Saved → %s', out)


# ──────────────────────────────────────────────────────────────────────────────
# 5. Correlation heatmap
# ──────────────────────────────────────────────────────────────────────────────

def plot_correlation(ft: pd.DataFrame) -> None:
    corr = ft[FEATURE_COLS].corr()

    fig, ax = plt.subplots(figsize=(9, 7))
    im = ax.imshow(corr.values, vmin=-1, vmax=1, cmap='RdBu_r', aspect='auto')
    fig.colorbar(im, ax=ax, shrink=0.8)

    ax.set_xticks(range(len(FEATURE_COLS)))
    ax.set_yticks(range(len(FEATURE_COLS)))
    ax.set_xticklabels(FEATURE_COLS, rotation=45, ha='right', fontsize=8)
    ax.set_yticklabels(FEATURE_COLS, fontsize=8)

    for i in range(len(FEATURE_COLS)):
        for j in range(len(FEATURE_COLS)):
            ax.text(j, i, f'{corr.values[i, j]:.2f}',
                    ha='center', va='center', fontsize=7,
                    color='white' if abs(corr.values[i, j]) > 0.6 else 'black')

    ax.set_title('Feature correlation matrix', fontsize=12, fontweight='bold')
    fig.tight_layout()
    out = OUTPUT_DIR / 'correlation_heatmap.png'
    fig.savefig(out, dpi=150)
    plt.close(fig)
    log.info('Saved → %s', out)


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info('Loading feature table (window=5s)...')
    ft = load_features(DEFAULT_WINDOW_SECONDS)
    log.info('Loaded %d windows × %d features', len(ft), len(FEATURE_COLS))

    print_phase_stats(ft)

    log.info('\nGenerating plots → %s', OUTPUT_DIR)
    plot_phase_distribution(ft)
    plot_timeseries(ft)
    plot_boxplots(ft)
    plot_correlation(ft)

    log.info('\n✓ EDA complete. Review the plots in %s', OUTPUT_DIR)
    log.info('  If attack phases show clearly different distributions from baseline,')
    log.info('  sign off and proceed to WP-07 (Isolation Forest training).')


if __name__ == '__main__':
    main()
