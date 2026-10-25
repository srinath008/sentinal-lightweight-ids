"""Bounded live context, kept outside the model's seven numeric inputs."""
from collections import Counter
from feature_engineering.events import Window


# WSL/systemd plumbing that dominates opensnoop counts without explaining the cause.
INFRASTRUCTURE = frozenset({'init', 'systemd', 'systemd-journal', 'systemd-journald', 'systemd-udevd', 'snapd'})


class EvidenceWindow(Window):
    def __init__(self):
        super().__init__()
        self.context_processes = Counter()
        self.exec_commands = Counter()
        self.sample_paths, self.sample_destinations = [], []
        self.context_truncated = False

    def add(self, source, event, phase='unlabeled'):
        super().add(source, event, phase)
        key = (event['pid'], str(event.get('pcomm', event.get('comm', 'unknown')))[:80], source)
        if key in self.context_processes or len(self.context_processes) < 200:
            self.context_processes[key] += 1
        else:
            self.context_truncated = True
        if source == 'execsnoop' and (event['pcomm'] in self.exec_commands or len(self.exec_commands) < 100):
            self.exec_commands[str(event['pcomm'])[:80]] += 1
        if source == 'opensnoop' and len(self.sample_paths) < 5:
            sample = str(event['path'])[:200]
            if sample not in self.sample_paths:
                self.sample_paths.append(sample)
        if source == 'tcpconnect' and len(self.sample_destinations) < 5:
            sample = f"{event['daddr']}:{event['dport']}"[:100]
            if sample not in self.sample_destinations:
                self.sample_destinations.append(sample)

    def row(self, *args):
        row = super().row(*args)
        ranked = [(k, n) for k, n in self.context_processes.most_common() if k[1] not in INFRASTRUCTURE]
        ranked = (ranked or self.context_processes.most_common())[:5]
        row['evidence'] = dict(processes=[dict(pid=k[0], name=k[1], source=k[2], observed_events=n)
                                          for k, n in ranked],
                               exec_commands=[dict(name=name, count=n) for name, n in self.exec_commands.most_common(5)],
                               sample_paths=self.sample_paths, sample_destinations=self.sample_destinations,
                               truncated=self.context_truncated)
        return row
