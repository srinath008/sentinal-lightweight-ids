"""Incident notification rates and delays on labelled held-out sessions."""
import pandas as pd
from inference.detector import IncidentGrouper


def incident_metrics(frame, scores, threshold, seconds, consecutive=2, cooldown=60):
    scored = frame[['session_id', 'window_index', 'window_start', 'phase']].copy()
    scored['anomaly'] = scores < threshold
    baseline_windows = int((scored.phase == 'baseline').sum())
    baseline_notifications = incident_starts = notifications = 0
    scenarios = []
    for sid, session in scored.groupby('session_id'):
        group = IncidentGrouper(consecutive, cooldown)
        active = False
        activity = []
        previous_index = None
        for row in session.sort_values('window_index').to_dict('records'):
            if previous_index is not None and row['window_index'] != previous_index + 1:
                # Reserved blocks have omitted gaps: do not carry incidents or
                # consecutive-window evidence across unobserved activity.
                group = IncidentGrouper(consecutive, cooldown)
                active = False
            previous_index = row['window_index']
            item = dict(row, scores={}, n_exec=0, n_unique_pcomm=0, n_open=0,
                        n_unique_paths=0, n_open_errors=0, n_tcp_connect=0, n_unique_daddr=0)
            incident = group.update(item)
            if incident:
                active = incident['type'] == 'incident_start'
                if active:
                    incident_starts += 1
                    notifications += int(incident['notification'])
                    baseline_notifications += int(incident['notification'] and row['phase'] == 'baseline')
            activity.append(dict(row, active=active))
        activity = pd.DataFrame(activity)
        # Separate contiguous labelled runs rather than merging repeated phases.
        activity['run'] = ((activity.phase != activity.phase.shift()) |
                           (activity.window_index.diff() != 1)).cumsum()
        for _, segment in activity.groupby('run'):
            phase = segment.phase.iloc[0]
            if not phase.startswith('attack_'):
                continue
            detected = segment[segment.active]
            delay = None if detected.empty else float(detected.window_start.iloc[0] - segment.window_start.iloc[0] + seconds)
            scenarios.append(dict(session_id=str(sid), phase=phase, detected=not detected.empty,
                                  incident_active_at_phase_start=bool(segment.active.iloc[0]),
                                  detection_delay_seconds=delay,
                                  note='Time until incident active in this phase; may carry over from earlier activity. Includes window completion, excludes ingestion overhead.'))
    return dict(consecutive=consecutive, cooldown_seconds=cooldown, incident_starts=incident_starts,
                notifications=notifications, baseline_notifications=baseline_notifications,
                baseline_notifications_per_hour=baseline_notifications * 3600 / (baseline_windows * seconds),
                scenarios=scenarios)
