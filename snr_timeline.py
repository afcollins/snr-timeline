#!/usr/bin/env python3
"""Generate SNR/NHC remediation timelines from yaml snapshots and controller logs."""

import argparse
import glob
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class Event:
    timestamp: datetime
    source: str
    node_name: str
    description: str
    level: str = "INFO"


@dataclass
class SNRSnapshot:
    observation_time: str
    node_name: str
    snr_name: str
    phase: str
    conditions: list = field(default_factory=list)
    strategy: str = ""
    template_name: str = ""


@dataclass
class Duration:
    label: str
    start: datetime
    end: datetime

    @property
    def delta(self) -> timedelta:
        return self.end - self.start


LOG_PATTERNS = [
    ("handling healthy node", "Node healthy, normal handling"),
    ("Node is going to match unhealthy condition", "Unhealthy pending — grace period starts"),
    ("Node matches unhealthy condition", "Node matches unhealthy condition"),
    ("Created remediation object", "SNR remediation CR created"),
    ("Remediation started by SNR", "SNR remediation started, pre-reboot prep begins"),
    ("NoExecute taint added", "NoExecute taint added"),
    ("Marking node as unschedulable", "Node marked unschedulable"),
    ("setting SNR's time to assume", "TimeAssumedRebooted set"),
    ("Node didn't reboot yet, waiting", "Node hasn't rebooted, waiting"),
    ("assumed to been rebooted", "Node assumed rebooted"),
    ("out-of-service taint added", "Out-of-service taint added"),
    ("waiting for terminating pod", "Waiting for terminating pod"),
    ("out-of-service taint removed", "Out-of-service taint removed"),
    ("finished deleting unhealthy node", "Node resources deleted"),
    ("deleted remediation CR", "Remediation CR deleted"),
    ("fencing completed", "Fencing cleanup"),
    ("mark healthy remediated", "Node marked schedulable"),
    ("NoExecute taint removed", "NoExecute taint removed"),
    ("finalizer removed", "Finalizer removed"),
    ("Remediation finished", "Remediation finished"),
    ("failed to update snr status", "ERROR: SNR status update failed (race condition)"),
    ("validate create", "SNR validate create"),
    ("pre-reboot not completed yet", "Pre-reboot not completed, preparing"),
    ("SNR already deleted", "SNR already deleted"),
    ("Node condition changed", "Node condition changed"),
]

SKIP_PATTERNS = [
    "mapper: found NHC",
    "lease",
    "CR already exists",
    "validate update",
    "adding NHC to reconcile queue",
    "Patching NHC status",
    "Attempting to obtain Node Lease",
    "handling unhealthy node",
    "waiting for unschedulable taint",
    "Reconciler error",
    "finalizer added",
    "AddFinalizer",
    "AddNoExecute",
    "MarkUnschedulable",
    "AddOutOfService",
    "RemoveOutOfService",
    "RemoveNoExecuteTaint",
    "RemoveFinalizer",
    "MarkNodeSchedulable",
    "DeleteResources",
    "UpdateTimeAssumedRebooted",
    "DetectedUnhealthy",
    "RemediationCreated",
    "RemediationStarted",
    "RemediationFinished",
]

DEDUP_PATTERNS = [
    "Waiting for terminating pod",
    "Pre-reboot not completed, preparing",
    "Node hasn't rebooted, waiting",
    "SNR already deleted",
    "Node matches unhealthy condition",
    "Node healthy",
    "Fencing cleanup",
]


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    ts_str = ts_str.strip().strip('"')
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]:
        try:
            return datetime.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Handle nanosecond timestamps by truncating to microseconds
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6})\d*Z?", ts_str)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def discover_files(directory: str) -> dict:
    snr_yamls = sorted(glob.glob(os.path.join(directory, "oc_g_snr.*.yaml")))
    log_files = sorted(glob.glob(os.path.join(directory, "logs.*")))
    return {"snr_yamls": snr_yamls, "log_files": log_files}


def load_yaml_doc(content: str) -> dict:
    if HAS_YAML:
        return yaml.safe_load(content)
    return _fallback_yaml_parse(content)


def _fallback_yaml_parse(content: str) -> dict:
    """Minimal regex-based YAML extraction when PyYAML unavailable."""
    result = {}
    if re.search(r'^kind:\s*List', content, re.MULTILINE):
        result['kind'] = 'List'
        items_match = re.search(r'^items:\s*\[\]', content, re.MULTILINE)
        if items_match:
            result['items'] = []
            return result
        result['items'] = _fallback_parse_items(content)
    else:
        result = _fallback_parse_single(content)
    return result


def _fallback_parse_items(content: str) -> list:
    """Parse items from a List-kind yaml using regex."""
    items = []
    item_blocks = re.split(r'^- apiVersion:', content, flags=re.MULTILINE)
    for block in item_blocks[1:]:
        block = "apiVersion:" + block
        items.append(_fallback_parse_single(block))
    return items


def _fallback_parse_single(content: str) -> dict:
    """Parse a single SNR object from yaml text using regex."""
    obj = {"metadata": {"annotations": {}}, "spec": {}, "status": {"conditions": []}}

    m = re.search(r'remediation\.medik8s\.io/node-name:\s*(\S+)', content)
    if m:
        obj["metadata"]["annotations"]["remediation.medik8s.io/node-name"] = m.group(1)

    m = re.search(r'remediation\.medik8s\.io/template-name:\s*(\S+)', content)
    if m:
        obj["metadata"]["annotations"]["remediation.medik8s.io/template-name"] = m.group(1)

    m = re.search(r'^\s+name:\s*(\S+)', content, re.MULTILINE)
    if m:
        obj["metadata"]["name"] = m.group(1)

    m = re.search(r'remediationStrategy:\s*(\S+)', content)
    if m:
        obj["spec"]["remediationStrategy"] = m.group(1)

    m = re.search(r'phase:\s*(\S+)', content)
    if m:
        obj["status"]["phase"] = m.group(1)

    conditions = []
    cond_blocks = re.findall(
        r'- lastTransitionTime:\s*"?([^"\n]+)"?\s*\n'
        r'\s+message:\s*"?([^"\n]*)"?\s*\n'
        r'\s+reason:\s*(\S+)\s*\n'
        r'\s+status:\s*"?(\S+)"?\s*\n'
        r'\s+type:\s*(\S+)',
        content,
    )
    for ltt, msg, reason, status, ctype in cond_blocks:
        conditions.append({
            "lastTransitionTime": ltt.strip('"'),
            "message": msg.strip('"'),
            "reason": reason,
            "status": status.strip('"'),
            "type": ctype,
        })
    obj["status"]["conditions"] = conditions

    return obj


def parse_snr_yamls(files: list) -> dict:
    """Parse SNR yaml files. Returns dict[node_name, list[SNRSnapshot]]."""
    snapshots_by_node = {}

    for filepath in files:
        filename = os.path.basename(filepath)
        # Extract observation time from filename
        time_match = re.search(r'(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})', filename)
        if time_match:
            obs_time_fmt = f"{time_match.group(2)}:{time_match.group(3)}:{time_match.group(4)}"
        else:
            # No timestamp in filename (e.g. oc_g_snr.f03-h06.yaml) — skip
            # These are standalone captures, not time-series snapshots
            continue

        with open(filepath, 'r') as f:
            content = f.read()

        doc = load_yaml_doc(content)
        if not doc:
            continue

        if doc.get('kind') == 'List':
            items = doc.get('items', [])
            if not items:
                # Empty list — record as deleted
                for node_name in snapshots_by_node:
                    snapshots_by_node[node_name].append(SNRSnapshot(
                        observation_time=obs_time_fmt,
                        node_name=node_name,
                        snr_name="",
                        phase="(SNR deleted — items list empty)",
                    ))
                continue
            for item in items:
                snap = _extract_snapshot(item, obs_time_fmt)
                if snap:
                    snapshots_by_node.setdefault(snap.node_name, []).append(snap)
        else:
            snap = _extract_snapshot(doc, obs_time_fmt)
            if snap:
                snapshots_by_node.setdefault(snap.node_name, []).append(snap)

    return snapshots_by_node


def _extract_snapshot(item: dict, obs_time: str) -> Optional[SNRSnapshot]:
    meta = item.get("metadata", {})
    annotations = meta.get("annotations", {})
    node_name = annotations.get("remediation.medik8s.io/node-name", "")
    if not node_name:
        return None

    template_name = annotations.get("remediation.medik8s.io/template-name", "")
    snr_name = meta.get("name", "")
    strategy = item.get("spec", {}).get("remediationStrategy", "")
    status = item.get("status", {})
    phase = status.get("phase", "")
    conditions = status.get("conditions", [])

    return SNRSnapshot(
        observation_time=obs_time,
        node_name=node_name,
        snr_name=snr_name,
        phase=phase,
        conditions=conditions,
        strategy=strategy,
        template_name=template_name,
    )


def _extract_node_from_line(line: str, node_names: set) -> Optional[str]:
    """Extract node name from log line by matching known node names."""
    for name in node_names:
        if name in line:
            return name
    return None


def _extract_log_timestamp(line: str) -> Optional[datetime]:
    m = re.match(r'^(\S+)\s', line)
    if m:
        return parse_timestamp(m.group(1))
    return None


def _extract_log_level(line: str) -> str:
    m = re.match(r'^\S+\s+(\w+)\s', line)
    if m:
        return m.group(1)
    return "INFO"


def _extract_extra_info(line: str, description: str) -> str:
    """Extract extra context from log line to enrich event description."""
    if "Unhealthy pending" in description:
        m = re.search(r'"duration left":\s*"([^"]+)"', line)
        if m:
            return f"{description} ({m.group(1)} remaining)"

    if "TimeAssumedRebooted set" in description:
        m = re.search(r'"time":\s*"([^"]+)"', line)
        if m:
            time_str = m.group(1).split(" +")[0]
            return f"{description} to {time_str}"

    if "Node hasn't rebooted" in description:
        m = re.search(r'"time left":\s*"([^"]+)"', line)
        if m:
            return f"{description} ({m.group(1)} left)"

    if "Waiting for terminating pod" in description:
        m = re.search(r'"pod name":\s*"([^"]+)"', line)
        if m:
            return f"{description} ({m.group(1)})"

    if "Node matches unhealthy condition" in description:
        ctype = re.search(r'"condition type":\s*"([^"]+)"', line)
        cstatus = re.search(r'"condition status":\s*"([^"]+)"', line)
        if ctype and cstatus:
            return f"{description} ({ctype.group(1)}={cstatus.group(1)})"

    return description


def _source_from_filename(filename: str) -> str:
    if "node-healthcheck" in filename:
        return "NHC log"
    if "self-node-remediation" in filename:
        return "SNR log"
    return "log"


def classify_log_line(line: str, node_names: set, source: str) -> Optional[Event]:
    """Classify a single log line into an Event or None."""
    node_name = _extract_node_from_line(line, node_names)
    if not node_name:
        return None

    # Check skip patterns first — these are [remediation] event duplicates
    # and mapper/lease noise
    for skip in SKIP_PATTERNS:
        if skip in line:
            return None

    ts = _extract_log_timestamp(line)
    if not ts:
        return None

    level = _extract_log_level(line)

    for pattern, description in LOG_PATTERNS:
        if pattern in line:
            description = _extract_extra_info(line, description)
            return Event(
                timestamp=ts,
                source=source,
                node_name=node_name,
                description=description,
                level=level,
            )

    return None


def parse_logs(files: list, node_names: set) -> dict:
    """Parse log files. Returns dict[node_name, list[Event]]."""
    events_by_node = {}

    for filepath in files:
        filename = os.path.basename(filepath)
        source = _source_from_filename(filename)

        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                event = classify_log_line(line, node_names, source)
                if event:
                    events_by_node.setdefault(event.node_name, []).append(event)

    # Dedup consecutive events with same description prefix
    for node_name in events_by_node:
        events_by_node[node_name] = _dedup_events(events_by_node[node_name])

    return events_by_node


def _dedup_events(events: list) -> list:
    """Remove consecutive duplicate events with identical descriptions."""
    if not events:
        return events
    result = [events[0]]
    for event in events[1:]:
        if event.description == result[-1].description:
            continue
        result.append(event)
    return result


def build_snr_state_table(snapshots: list) -> list:
    """Build state table rows from SNR snapshots."""
    rows = []
    for snap in snapshots:
        processing = "—"
        succeeded = "—"
        reason = "—"
        for cond in snap.conditions:
            if cond.get("type") == "Processing":
                processing = cond.get("status", "—")
            elif cond.get("type") == "Succeeded":
                succeeded = cond.get("status", "—")
                reason = cond.get("reason", "—")
        rows.append({
            "time": snap.observation_time,
            "phase": snap.phase,
            "processing": processing,
            "succeeded": succeeded,
            "reason": reason,
        })
    return rows


def yaml_events_from_snapshots(snapshots: list) -> list:
    """Generate timeline events from SNR yaml snapshot transitions."""
    events = []
    prev_phase = None
    for snap in snapshots:
        if snap.phase != prev_phase:
            desc_parts = [f"SNR status: phase={snap.phase}"]
            for cond in snap.conditions:
                desc_parts.append(
                    f"{cond.get('type')}={cond.get('status')}"
                )
            if snap.phase == "(SNR deleted — items list empty)":
                desc = "SNR list empty — CR deleted"
            else:
                desc = ", ".join(desc_parts)

            # Use condition lastTransitionTime if available, else observation_time
            ts = None
            for cond in snap.conditions:
                ltt = cond.get("lastTransitionTime")
                if ltt:
                    ts = parse_timestamp(ltt)
                    break
            if not ts and len(snap.observation_time) == 8:
                # observation_time is HH:MM:SS — build a minimal parseable timestamp
                # Use date from first condition of first snapshot if available
                ts = parse_timestamp(f"2026-01-01T{snap.observation_time}Z")

            if ts:
                events.append(Event(
                    timestamp=ts,
                    source="SNR yaml",
                    node_name=snap.node_name,
                    description=desc,
                ))
            prev_phase = snap.phase
    return events


def merge_timeline(log_events: list, yaml_events: list) -> list:
    """Merge and sort events by timestamp."""
    all_events = log_events + yaml_events
    all_events.sort(key=lambda e: e.timestamp)
    return all_events


def compute_durations(events: list) -> list:
    """Compute key interval durations from event timeline."""
    durations = []
    milestones = {}

    for event in events:
        desc = event.description
        if "Node matches unhealthy condition" in desc and "Unhealthy" not in desc:
            milestones.setdefault("unhealthy_detected", event.timestamp)
        elif "SNR remediation CR created" in desc or "SNR validate create" in desc:
            milestones.setdefault("snr_created", event.timestamp)
        elif "Node assumed rebooted" in desc:
            milestones.setdefault("assumed_rebooted", event.timestamp)
        elif "Out-of-service taint removed" in desc or "Node resources deleted" in desc:
            milestones.setdefault("fencing_complete", event.timestamp)
        elif "Remediation CR deleted" in desc or "Remediation finished" in desc:
            milestones.setdefault("cleanup_done", event.timestamp)

    if "unhealthy_detected" in milestones and "snr_created" in milestones:
        durations.append(Duration(
            "Unhealthy detection → SNR created",
            milestones["unhealthy_detected"],
            milestones["snr_created"],
        ))

    if "snr_created" in milestones and "assumed_rebooted" in milestones:
        durations.append(Duration(
            "SNR created → assumed rebooted",
            milestones["snr_created"],
            milestones["assumed_rebooted"],
        ))

    if "assumed_rebooted" in milestones and "fencing_complete" in milestones:
        durations.append(Duration(
            "Assumed rebooted → fencing complete",
            milestones["assumed_rebooted"],
            milestones["fencing_complete"],
        ))

    if "fencing_complete" in milestones and "cleanup_done" in milestones:
        durations.append(Duration(
            "Fencing complete → node healthy + cleanup",
            milestones["fencing_complete"],
            milestones["cleanup_done"],
        ))

    if "snr_created" in milestones and "cleanup_done" in milestones:
        durations.append(Duration(
            "**Total remediation**",
            milestones["snr_created"],
            milestones["cleanup_done"],
        ))

    return durations


def detect_notable(events: list) -> list:
    """Detect notable observations from events."""
    notable = []
    has_race = False
    has_oos = False
    waiting_pods = set()

    for event in events:
        if "failed to update snr status" in event.description.lower() or "race" in event.description.lower():
            has_race = True
        if "out-of-service taint added" in event.description.lower():
            has_oos = True
        m = re.search(r'Waiting for terminating pod \(([^)]+)\)', event.description)
        if m:
            waiting_pods.add(m.group(1))

    if has_race:
        notable.append("**Race at cleanup**: NHC deleted SNR CR before SNR controller finished status update → harmless \"not found\" error in SNR log")

    if has_oos:
        notable.append("**Strategy**: `outofservicetaint` — no actual reboot performed; node assumed rebooted after timeout")

    if waiting_pods:
        pods_str = ", ".join(f"`{p}`" for p in sorted(waiting_pods))
        notable.append(f"**Pod evacuation**: waited for {len(waiting_pods)} pods: {pods_str}")

    return notable


def format_duration(td: timedelta) -> str:
    total_seconds = int(td.total_seconds())
    minutes, seconds = divmod(abs(total_seconds), 60)
    if minutes > 0:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


def format_node_report(
    node_name: str,
    snr_name: str,
    strategy: str,
    template_name: str,
    state_table: list,
    timeline: list,
    durations: list,
    notable: list,
) -> str:
    lines = []
    lines.append(f"## Node: {node_name}")
    if snr_name:
        lines.append(f"## SNR CR: {snr_name}")
    if strategy:
        lines.append(f"## Strategy: {strategy} ({template_name})")
    lines.append("")
    lines.append("---")
    lines.append("")

    # SNR State Table
    lines.append("## SNR Object State Over Time (from yaml snapshots)")
    lines.append("")
    lines.append("| Snapshot Time | Phase | Processing | Succeeded | Reason |")
    lines.append("|---|---|---|---|---|")
    for row in state_table:
        lines.append(f"| {row['time']} | {row['phase']} | {row['processing']} | {row['succeeded']} | {row['reason']} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Correlated Timeline
    lines.append("## Correlated Timeline")
    lines.append("")
    lines.append("| Time (UTC) | Source | Event |")
    lines.append("|---|---|---|")
    for event in timeline:
        ts_str = event.timestamp.strftime("%H:%M:%S")
        lines.append(f"| {ts_str} | {event.source} | {event.description} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Key Durations
    lines.append("## Key Durations")
    lines.append("")
    lines.append("| Interval | Duration |")
    lines.append("|---|---|")
    for dur in durations:
        start_str = dur.start.strftime("%H:%M:%S")
        end_str = dur.end.strftime("%H:%M:%S")
        dur_str = format_duration(dur.delta)
        lines.append(f"| {dur.label} | {dur_str} ({start_str} → {end_str}) |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Notable Observations
    if notable:
        lines.append("## Notable Observations")
        lines.append("")
        for i, note in enumerate(notable, 1):
            lines.append(f"{i}. {note}")
        lines.append("")

    return "\n".join(lines)


def format_summary(node_reports: dict) -> str:
    """Multi-node summary header."""
    if len(node_reports) <= 1:
        return ""
    lines = ["# SNR/NHC Remediation Timeline Summary", ""]
    lines.append(f"**Nodes analyzed**: {len(node_reports)}")
    lines.append("")
    lines.append("| Node | SNR CR | Total Duration |")
    lines.append("|---|---|---|")
    for node_name, info in sorted(node_reports.items()):
        dur_str = info.get("total_duration", "—")
        lines.append(f"| {node_name} | {info.get('snr_name', '—')} | {dur_str} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def run(directory: str, node_filter: Optional[str] = None) -> str:
    """Main processing pipeline. Returns markdown string."""
    files = discover_files(directory)

    if not files["snr_yamls"]:
        return "No SNR yaml files found in directory."

    # Parse yamls first to discover node names
    snapshots_by_node = parse_snr_yamls(files["snr_yamls"])
    node_names = set(snapshots_by_node.keys())

    if not node_names:
        return "No SNR objects found in yaml files."

    # Filter nodes if requested
    if node_filter:
        node_names = {n for n in node_names if node_filter in n}
        if not node_names:
            return f"No nodes matching '{node_filter}' found."

    # Parse logs
    log_events_by_node = parse_logs(files["log_files"], node_names)

    # Build reports
    node_reports_meta = {}
    reports = []

    for node_name in sorted(node_names):
        snapshots = snapshots_by_node.get(node_name, [])
        log_events = log_events_by_node.get(node_name, [])

        # Get metadata from first snapshot
        snr_name = ""
        strategy = ""
        template_name = ""
        for s in snapshots:
            if s.snr_name:
                snr_name = s.snr_name
            if s.strategy:
                strategy = s.strategy
            if s.template_name:
                template_name = s.template_name

        state_table = build_snr_state_table(snapshots)
        yaml_events = yaml_events_from_snapshots(snapshots)
        timeline = merge_timeline(log_events, yaml_events)
        durations = compute_durations(timeline)
        notable = detect_notable(timeline)

        total_str = "—"
        for d in durations:
            if "Total" in d.label:
                total_str = format_duration(d.delta)

        node_reports_meta[node_name] = {
            "snr_name": snr_name,
            "total_duration": total_str,
        }

        report = format_node_report(
            node_name, snr_name, strategy, template_name,
            state_table, timeline, durations, notable,
        )
        reports.append(report)

    output = ""
    summary = format_summary(node_reports_meta)
    if summary:
        output += summary

    output += "\n\n".join(reports)
    return output


def main():
    parser = argparse.ArgumentParser(description="Generate SNR/NHC remediation timeline")
    parser.add_argument("directory", nargs="?", default=".", help="Directory containing yaml/log files")
    parser.add_argument("--node", help="Filter to specific node (substring match)")
    parser.add_argument("--all", action="store_true", help="Show all nodes (default)")
    args = parser.parse_args()

    result = run(args.directory, node_filter=args.node)
    print(result)


if __name__ == "__main__":
    main()
