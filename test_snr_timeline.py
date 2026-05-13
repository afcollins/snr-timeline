"""Tests for snr_timeline.py"""

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from snr_timeline import (
    Event,
    SNRSnapshot,
    Duration,
    parse_timestamp,
    discover_files,
    parse_snr_yamls,
    parse_logs,
    classify_log_line,
    build_snr_state_table,
    yaml_events_from_snapshots,
    merge_timeline,
    compute_durations,
    detect_notable,
    format_duration,
    format_node_report,
    run,
    _dedup_events,
    _extract_extra_info,
    _source_from_filename,
)


# --- Fixtures ---

SAMPLE_SNR_LIST_YAML = """\
apiVersion: v1
items:
- apiVersion: self-node-remediation.medik8s.io/v1alpha1
  kind: SelfNodeRemediation
  metadata:
    annotations:
      remediation.medik8s.io/node-name: node-a
      remediation.medik8s.io/template-name: self-node-remediation-outofservicetaint-strategy-template
    creationTimestamp: "2026-05-12T19:09:46Z"
    name: node-a-abc12
    namespace: openshift-workload-availability
  spec:
    remediationStrategy: OutOfServiceTaint
  status:
    conditions:
    - lastTransitionTime: "2026-05-12T19:09:47Z"
      message: ""
      reason: RemediationStarted
      status: "True"
      type: Processing
    - lastTransitionTime: "2026-05-12T19:09:47Z"
      message: ""
      reason: RemediationStarted
      status: Unknown
      type: Succeeded
    phase: Pre-Reboot-Completed
    timeAssumedRebooted: "2026-05-12T19:13:08Z"
kind: List
metadata:
  resourceVersion: ""
"""

SAMPLE_SNR_FENCED_YAML = """\
apiVersion: v1
items:
- apiVersion: self-node-remediation.medik8s.io/v1alpha1
  kind: SelfNodeRemediation
  metadata:
    annotations:
      remediation.medik8s.io/node-name: node-a
      remediation.medik8s.io/template-name: self-node-remediation-outofservicetaint-strategy-template
    creationTimestamp: "2026-05-12T19:09:46Z"
    name: node-a-abc12
    namespace: openshift-workload-availability
  spec:
    remediationStrategy: OutOfServiceTaint
  status:
    conditions:
    - lastTransitionTime: "2026-05-12T19:13:24Z"
      message: ""
      reason: RemediationFinishedSuccessfully
      status: "False"
      type: Processing
    - lastTransitionTime: "2026-05-12T19:13:24Z"
      message: ""
      reason: RemediationFinishedSuccessfully
      status: "True"
      type: Succeeded
    phase: Fencing-Completed
    timeAssumedRebooted: "2026-05-12T19:13:08Z"
kind: List
metadata:
  resourceVersion: ""
"""

SAMPLE_SNR_EMPTY_YAML = """\
apiVersion: v1
items: []
kind: List
metadata:
  resourceVersion: ""
"""

SAMPLE_NHC_LOG = """\
2026-05-12T18:59:44.924561750Z	INFO	controllers.NodeHealthCheck	handling healthy node	{"NodeHealthCheck name": "nhc-worker-self", "node": "node-a"}
2026-05-12T19:08:36.894191373Z	INFO	controllers.NodeHealthCheck	Node is going to match unhealthy condition	{"node": "node-a", "condition type": "Ready", "condition status": "Unknown", "duration left": "59.098s"}
2026-05-12T19:09:41.972989352Z	INFO	controllers.NodeHealthCheck	Node matches unhealthy condition	{"node": "node-a", "condition type": "Ready", "condition status": "Unknown"}
2026-05-12T19:09:46.736547123Z	DEBUG	events	[remediation] Created remediation object for node node-a	{"type": "Normal", "reason": "RemediationCreated"}
2026-05-12T19:14:43.123456789Z	INFO	controllers.NodeHealthCheck	handling healthy node	{"NodeHealthCheck name": "nhc-worker-self", "node": "node-a"}
2026-05-12T19:14:47.965655241Z	DEBUG	events	[remediation] deleted remediation CR	{"node": "node-a"}
"""

SAMPLE_SNR_LOG = """\
2026-05-12T19:09:46.734449815Z	INFO	selfnoderemediation-resource	validate create	{"name": "node-a-abc12"}
2026-05-12T19:09:46.838090595Z	DEBUG	events	[remediation] Remediation started by SNR manager	{"type": "Normal", "object": {"name":"node-a-abc12"}, "reason": "RemediationStarted"}
2026-05-12T19:09:47.366450743Z	INFO	controllers.SelfNodeRemediation	NoExecute taint added	{"selfnoderemediation": {"name":"node-a-abc12"}, "node name": "node-a"}
2026-05-12T19:09:47.366487739Z	INFO	controllers.SelfNodeRemediation	Marking node as unschedulable	{"selfnoderemediation": {"name":"node-a-abc12"}, "node name": "node-a"}
2026-05-12T19:09:48.388186530Z	INFO	controllers.SelfNodeRemediation	setting SNR's time to assume node has been rebooted	{"selfnoderemediation": {"name":"node-a-abc12"}, "node name": "node-a", "time": "2026-05-12 19:13:08.388185618 +0000 UTC"}
2026-05-12T19:09:48.394379276Z	INFO	controllers.SelfNodeRemediation	Node didn't reboot yet, waiting for it to reboot	{"selfnoderemediation": {"name":"node-a-abc12"}, "node name": "node-a", "time left": "3m20s"}
2026-05-12T19:13:09.005681849Z	INFO	controllers.SelfNodeRemediation	TimeAssumedRebooted is old. The unhealthy node assumed to been rebooted	{"selfnoderemediation": {"name":"node-a-abc12"}, "node name": "node-a"}
2026-05-12T19:13:09.023097336Z	INFO	controllers.SelfNodeRemediation	out-of-service taint added	{"selfnoderemediation": {"name":"node-a-abc12"}, "node name": "node-a"}
2026-05-12T19:13:09.102932432Z	INFO	controllers.SelfNodeRemediation	waiting for terminating pod 	{"selfnoderemediation": {"name":"node-a-abc12"}, "pod name": "diskmaker-manager-9l79h", "phase": "Running"}
2026-05-12T19:13:14.196587807Z	INFO	controllers.SelfNodeRemediation	waiting for terminating pod 	{"selfnoderemediation": {"name":"node-a-abc12"}, "pod name": "diskmaker-manager-9l79h", "phase": "Running"}
2026-05-12T19:13:19.296176367Z	INFO	controllers.SelfNodeRemediation	waiting for terminating pod 	{"selfnoderemediation": {"name":"node-a-abc12"}, "pod name": "dns-default-g5sd9", "phase": "Running"}
2026-05-12T19:13:24.495570099Z	INFO	controllers.SelfNodeRemediation	out-of-service taint removed	{"selfnoderemediation": {"name":"node-a-abc12"}, "node name": "node-a"}
2026-05-12T19:13:24.495699570Z	DEBUG	events	[remediation] Remediation process - finished deleting unhealthy node resources	{"type": "Normal", "object": {"name":"node-a"}, "reason": "DeleteResources"}
2026-05-12T19:14:47.965655241Z	INFO	controllers.SelfNodeRemediation	fencing completed, cleaning up	{"selfnoderemediation": {"name":"node-a-abc12"}}
2026-05-12T19:14:48.988995968Z	INFO	controllers.SelfNodeRemediation	NoExecute taint removed	{"selfnoderemediation": {"name":"node-a-abc12"}}
2026-05-12T19:14:49.002105084Z	INFO	controllers.SelfNodeRemediation	finalizer removed	{"selfnoderemediation": {"name":"node-a-abc12"}}
2026-05-12T19:14:49.002217331Z	DEBUG	events	[remediation] Remediation finished	{"type": "Normal", "object": {"name":"node-a-abc12"}, "reason": "RemediationFinished"}
2026-05-12T19:14:49.004788825Z	ERROR	controllers.SelfNodeRemediation	failed to update snr status	{"selfnoderemediation": {"name":"node-a-abc12"}, "error": "not found"}
"""


@pytest.fixture
def test_dir(tmp_path):
    """Create temp directory with sample test data."""
    # Write SNR yamls
    (tmp_path / "oc_g_snr.2026-05-12-191215.yaml").write_text(SAMPLE_SNR_LIST_YAML)
    (tmp_path / "oc_g_snr.2026-05-12-191326.yaml").write_text(SAMPLE_SNR_FENCED_YAML)
    (tmp_path / "oc_g_snr.2026-05-12-191457.yaml").write_text(SAMPLE_SNR_EMPTY_YAML)

    # Write logs
    (tmp_path / "logs.node-healthcheck-controller-manager-abc.2026-05-12-200359.log").write_text(SAMPLE_NHC_LOG)
    (tmp_path / "logs.self-node-remediation-controller-manager-xyz.2026-05-12-200455.log").write_text(SAMPLE_SNR_LOG)

    return tmp_path


# --- parse_timestamp ---

class TestParseTimestamp:
    def test_iso_with_z(self):
        ts = parse_timestamp("2026-05-12T19:09:46Z")
        assert ts == datetime(2026, 5, 12, 19, 9, 46, tzinfo=timezone.utc)

    def test_iso_with_fractional(self):
        ts = parse_timestamp("2026-05-12T19:09:46.123456Z")
        assert ts.second == 46
        assert ts.microsecond == 123456

    def test_nanosecond_truncation(self):
        ts = parse_timestamp("2026-05-12T19:09:46.123456789Z")
        assert ts is not None
        assert ts.microsecond == 123456

    def test_invalid(self):
        assert parse_timestamp("not-a-date") is None

    def test_quoted(self):
        ts = parse_timestamp('"2026-05-12T19:09:46Z"')
        assert ts is not None


# --- discover_files ---

class TestDiscoverFiles:
    def test_finds_files(self, test_dir):
        files = discover_files(str(test_dir))
        assert len(files["snr_yamls"]) == 3
        assert len(files["log_files"]) == 2

    def test_empty_dir(self, tmp_path):
        files = discover_files(str(tmp_path))
        assert files["snr_yamls"] == []
        assert files["log_files"] == []

    def test_sorted_order(self, test_dir):
        files = discover_files(str(test_dir))
        assert "191215" in files["snr_yamls"][0]
        assert "191457" in files["snr_yamls"][-1]


# --- parse_snr_yamls ---

class TestParseSNRYamls:
    def test_basic_parse(self, test_dir):
        files = discover_files(str(test_dir))
        snapshots = parse_snr_yamls(files["snr_yamls"])
        assert "node-a" in snapshots
        assert len(snapshots["node-a"]) >= 2

    def test_snapshot_fields(self, test_dir):
        files = discover_files(str(test_dir))
        snapshots = parse_snr_yamls(files["snr_yamls"])
        first = snapshots["node-a"][0]
        assert first.node_name == "node-a"
        assert first.snr_name == "node-a-abc12"
        assert first.phase == "Pre-Reboot-Completed"
        assert first.strategy == "OutOfServiceTaint"
        assert len(first.conditions) == 2

    def test_phase_progression(self, test_dir):
        files = discover_files(str(test_dir))
        snapshots = parse_snr_yamls(files["snr_yamls"])
        phases = [s.phase for s in snapshots["node-a"]]
        assert "Pre-Reboot-Completed" in phases
        assert "Fencing-Completed" in phases

    def test_empty_list_recorded(self, test_dir):
        files = discover_files(str(test_dir))
        snapshots = parse_snr_yamls(files["snr_yamls"])
        last = snapshots["node-a"][-1]
        assert "deleted" in last.phase.lower()

    def test_skips_non_timestamped_files(self, tmp_path):
        (tmp_path / "oc_g_snr.f03-h06.yaml").write_text(SAMPLE_SNR_LIST_YAML)
        files = discover_files(str(tmp_path))
        snapshots = parse_snr_yamls(files["snr_yamls"])
        assert len(snapshots) == 0


# --- classify_log_line ---

class TestClassifyLogLine:
    def test_healthy_node(self):
        line = '2026-05-12T18:59:44.924Z\tINFO\tcontrollers.NodeHealthCheck\thandling healthy node\t{"node": "node-a"}'
        event = classify_log_line(line, {"node-a"}, "NHC log")
        assert event is not None
        assert "Node healthy" in event.description
        assert event.node_name == "node-a"

    def test_unhealthy_pending(self):
        line = '2026-05-12T19:08:36.894Z\tINFO\tcontrollers.NodeHealthCheck\tNode is going to match unhealthy condition\t{"node": "node-a", "duration left": "59.098s"}'
        event = classify_log_line(line, {"node-a"}, "NHC log")
        assert event is not None
        assert "Unhealthy pending" in event.description
        assert "59.098s" in event.description

    def test_unhealthy_match(self):
        line = '2026-05-12T19:09:41.972Z\tINFO\tcontrollers.NodeHealthCheck\tNode matches unhealthy condition\t{"node": "node-a", "condition type": "Ready", "condition status": "Unknown"}'
        event = classify_log_line(line, {"node-a"}, "NHC log")
        assert event is not None
        assert "Ready=Unknown" in event.description

    def test_noexecute_taint(self):
        line = '2026-05-12T19:09:47.366Z\tINFO\tcontrollers.SelfNodeRemediation\tNoExecute taint added\t{"node name": "node-a"}'
        event = classify_log_line(line, {"node-a"}, "SNR log")
        assert event is not None
        assert event.description == "NoExecute taint added"

    def test_waiting_for_pod(self):
        line = '2026-05-12T19:13:09.102Z\tINFO\tcontrollers.SelfNodeRemediation\twaiting for terminating pod \t{"selfnoderemediation": {"name":"node-a-abc12"}, "pod name": "diskmaker-manager-9l79h"}'
        event = classify_log_line(line, {"node-a"}, "SNR log")
        assert event is not None
        assert "diskmaker-manager-9l79h" in event.description

    def test_skip_mapper(self):
        line = '2026-05-12T19:09:47.348Z\tINFO\tcontrollers.NodeHealthCheck\tmapper: found NHC for remediation CR\t{"NHC Name": "nhc-worker-self", "Remediation CR Name": "node-a-abc12"}'
        event = classify_log_line(line, {"node-a"}, "NHC log")
        assert event is None

    def test_skip_validate_update(self):
        line = '2026-05-12T19:09:47.346Z\tINFO\tselfnoderemediation-resource\tvalidate update\t{"name": "node-a-abc12"}'
        event = classify_log_line(line, {"node-a"}, "SNR log")
        assert event is None

    def test_no_matching_node(self):
        line = '2026-05-12T18:59:44.924Z\tINFO\tcontrollers.NodeHealthCheck\thandling healthy node\t{"node": "other-node"}'
        event = classify_log_line(line, {"node-a"}, "NHC log")
        assert event is None

    def test_error_level(self):
        line = '2026-05-12T19:14:49.004Z\tERROR\tcontrollers.SelfNodeRemediation\tfailed to update snr status\t{"selfnoderemediation": {"name":"node-a-abc12"}, "error": "not found"}'
        event = classify_log_line(line, {"node-a"}, "SNR log")
        assert event is not None
        assert event.level == "ERROR"
        assert "race" in event.description.lower()

    def test_time_assumed_rebooted(self):
        line = '2026-05-12T19:09:48.388Z\tINFO\tcontrollers.SelfNodeRemediation\tsetting SNR\'s time to assume node has been rebooted\t{"node name": "node-a", "time": "2026-05-12 19:13:08.388 +0000 UTC"}'
        event = classify_log_line(line, {"node-a"}, "SNR log")
        assert event is not None
        assert "TimeAssumedRebooted set" in event.description
        assert "19:13:08" in event.description


# --- parse_logs ---

class TestParseLogs:
    def test_parses_both_logs(self, test_dir):
        files = discover_files(str(test_dir))
        events = parse_logs(files["log_files"], {"node-a"})
        assert "node-a" in events
        assert len(events["node-a"]) > 5

    def test_dedup_waiting_pods(self, test_dir):
        files = discover_files(str(test_dir))
        events = parse_logs(files["log_files"], {"node-a"})
        waiting_events = [e for e in events["node-a"] if "Waiting for terminating pod" in e.description]
        pod_names = [e.description for e in waiting_events]
        # diskmaker appears twice consecutively — should be deduped to 1,
        # then dns-default is different so stays
        assert len(waiting_events) == 2

    def test_source_attribution(self, test_dir):
        files = discover_files(str(test_dir))
        events = parse_logs(files["log_files"], {"node-a"})
        sources = {e.source for e in events["node-a"]}
        assert "NHC log" in sources
        assert "SNR log" in sources


# --- _dedup_events ---

class TestDedupEvents:
    def test_empty(self):
        assert _dedup_events([]) == []

    def test_no_dedup_needed(self):
        events = [
            Event(datetime(2026, 1, 1, tzinfo=timezone.utc), "src", "n", "Event A"),
            Event(datetime(2026, 1, 1, tzinfo=timezone.utc), "src", "n", "Event B"),
        ]
        assert len(_dedup_events(events)) == 2

    def test_dedup_consecutive(self):
        events = [
            Event(datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc), "src", "n", "Waiting for terminating pod (a)"),
            Event(datetime(2026, 1, 1, 0, 0, 2, tzinfo=timezone.utc), "src", "n", "Waiting for terminating pod (a)"),
            Event(datetime(2026, 1, 1, 0, 0, 3, tzinfo=timezone.utc), "src", "n", "Waiting for terminating pod (b)"),
        ]
        result = _dedup_events(events)
        assert len(result) == 2
        assert "(a)" in result[0].description
        assert "(b)" in result[1].description


# --- build_snr_state_table ---

class TestBuildSNRStateTable:
    def test_basic(self):
        snapshots = [
            SNRSnapshot("19:12:15", "node-a", "node-a-abc12", "Pre-Reboot-Completed",
                        [{"type": "Processing", "status": "True", "reason": "RemediationStarted"},
                         {"type": "Succeeded", "status": "Unknown", "reason": "RemediationStarted"}]),
        ]
        table = build_snr_state_table(snapshots)
        assert len(table) == 1
        assert table[0]["phase"] == "Pre-Reboot-Completed"
        assert table[0]["processing"] == "True"
        assert table[0]["succeeded"] == "Unknown"
        assert table[0]["reason"] == "RemediationStarted"

    def test_deleted_snapshot(self):
        snapshots = [
            SNRSnapshot("19:14:57", "node-a", "", "(SNR deleted — items list empty)", []),
        ]
        table = build_snr_state_table(snapshots)
        assert table[0]["processing"] == "—"


# --- yaml_events_from_snapshots ---

class TestYamlEvents:
    def test_phase_change_events(self):
        snapshots = [
            SNRSnapshot("19:12:15", "node-a", "node-a-abc12", "Pre-Reboot-Completed",
                        [{"type": "Processing", "status": "True", "reason": "R",
                          "lastTransitionTime": "2026-05-12T19:09:47Z"}]),
            SNRSnapshot("19:13:11", "node-a", "node-a-abc12", "Reboot-Completed",
                        [{"type": "Processing", "status": "True", "reason": "R",
                          "lastTransitionTime": "2026-05-12T19:09:47Z"}]),
        ]
        events = yaml_events_from_snapshots(snapshots)
        assert len(events) == 2
        assert "Pre-Reboot" in events[0].description
        assert "Reboot-Completed" in events[1].description

    def test_no_duplicate_for_same_phase(self):
        snapshots = [
            SNRSnapshot("19:12:15", "node-a", "node-a-abc12", "Pre-Reboot-Completed",
                        [{"type": "Processing", "status": "True", "reason": "R",
                          "lastTransitionTime": "2026-05-12T19:09:47Z"}]),
            SNRSnapshot("19:12:56", "node-a", "node-a-abc12", "Pre-Reboot-Completed",
                        [{"type": "Processing", "status": "True", "reason": "R",
                          "lastTransitionTime": "2026-05-12T19:09:47Z"}]),
        ]
        events = yaml_events_from_snapshots(snapshots)
        assert len(events) == 1

    def test_deleted_event(self):
        snapshots = [
            SNRSnapshot("19:14:57", "node-a", "", "(SNR deleted — items list empty)", []),
        ]
        events = yaml_events_from_snapshots(snapshots)
        assert len(events) == 1
        assert "deleted" in events[0].description.lower()


# --- merge_timeline ---

class TestMergeTimeline:
    def test_sorts_by_timestamp(self):
        e1 = Event(datetime(2026, 1, 1, 19, 0, 0, tzinfo=timezone.utc), "A", "n", "first")
        e2 = Event(datetime(2026, 1, 1, 18, 0, 0, tzinfo=timezone.utc), "B", "n", "second")
        merged = merge_timeline([e1], [e2])
        assert merged[0].description == "second"
        assert merged[1].description == "first"

    def test_empty(self):
        assert merge_timeline([], []) == []


# --- compute_durations ---

class TestComputeDurations:
    def test_full_lifecycle(self):
        events = [
            Event(datetime(2026, 1, 1, 19, 9, 41, tzinfo=timezone.utc), "NHC", "n", "Node matches unhealthy condition"),
            Event(datetime(2026, 1, 1, 19, 9, 46, tzinfo=timezone.utc), "SNR", "n", "SNR validate create"),
            Event(datetime(2026, 1, 1, 19, 13, 9, tzinfo=timezone.utc), "SNR", "n", "Node assumed rebooted"),
            Event(datetime(2026, 1, 1, 19, 13, 24, tzinfo=timezone.utc), "SNR", "n", "Out-of-service taint removed"),
            Event(datetime(2026, 1, 1, 19, 14, 47, tzinfo=timezone.utc), "NHC", "n", "Remediation CR deleted"),
        ]
        durations = compute_durations(events)
        labels = [d.label for d in durations]
        assert "Unhealthy detection → SNR created" in labels
        assert "SNR created → assumed rebooted" in labels
        assert "Assumed rebooted → fencing complete" in labels
        assert any("Total" in l for l in labels)

    def test_total_duration_value(self):
        events = [
            Event(datetime(2026, 1, 1, 19, 9, 41, tzinfo=timezone.utc), "NHC", "n", "Node matches unhealthy condition"),
            Event(datetime(2026, 1, 1, 19, 9, 46, tzinfo=timezone.utc), "SNR", "n", "SNR validate create"),
            Event(datetime(2026, 1, 1, 19, 14, 47, tzinfo=timezone.utc), "NHC", "n", "Remediation finished"),
        ]
        durations = compute_durations(events)
        total = [d for d in durations if "Total" in d.label][0]
        assert total.delta == timedelta(minutes=5, seconds=1)

    def test_partial_events(self):
        events = [
            Event(datetime(2026, 1, 1, 19, 9, 46, tzinfo=timezone.utc), "SNR", "n", "SNR validate create"),
            Event(datetime(2026, 1, 1, 19, 13, 9, tzinfo=timezone.utc), "SNR", "n", "Node assumed rebooted"),
        ]
        durations = compute_durations(events)
        assert len(durations) == 1
        assert "SNR created → assumed rebooted" in durations[0].label


# --- detect_notable ---

class TestDetectNotable:
    def test_race_detected(self):
        events = [
            Event(datetime(2026, 1, 1, tzinfo=timezone.utc), "SNR", "n",
                  "ERROR: SNR status update failed (race condition)"),
        ]
        notable = detect_notable(events)
        assert any("Race" in n for n in notable)

    def test_oos_strategy(self):
        events = [
            Event(datetime(2026, 1, 1, tzinfo=timezone.utc), "SNR", "n",
                  "Out-of-service taint added"),
        ]
        notable = detect_notable(events)
        assert any("outofservicetaint" in n for n in notable)

    def test_pod_evacuation(self):
        events = [
            Event(datetime(2026, 1, 1, tzinfo=timezone.utc), "SNR", "n",
                  "Waiting for terminating pod (diskmaker-manager-9l79h)"),
            Event(datetime(2026, 1, 1, tzinfo=timezone.utc), "SNR", "n",
                  "Waiting for terminating pod (dns-default-abc)"),
        ]
        notable = detect_notable(events)
        pod_note = [n for n in notable if "Pod evacuation" in n][0]
        assert "2 pods" in pod_note
        assert "diskmaker" in pod_note
        assert "dns-default" in pod_note


# --- format_duration ---

class TestFormatDuration:
    def test_minutes_and_seconds(self):
        assert format_duration(timedelta(minutes=5, seconds=1)) == "5m01s"

    def test_seconds_only(self):
        assert format_duration(timedelta(seconds=15)) == "15s"

    def test_zero(self):
        assert format_duration(timedelta(0)) == "0s"


# --- _source_from_filename ---

class TestSourceFromFilename:
    def test_nhc(self):
        assert _source_from_filename("logs.node-healthcheck-controller-manager-abc.log") == "NHC log"

    def test_snr(self):
        assert _source_from_filename("logs.self-node-remediation-controller-manager-xyz.log") == "SNR log"

    def test_unknown(self):
        assert _source_from_filename("logs.something-else.log") == "log"


# --- _extract_extra_info ---

class TestExtractExtraInfo:
    def test_grace_period(self):
        line = '{"duration left": "59.098s"}'
        result = _extract_extra_info(line, "Unhealthy pending — grace period starts")
        assert "59.098s" in result

    def test_no_match_passthrough(self):
        result = _extract_extra_info("some line", "NoExecute taint added")
        assert result == "NoExecute taint added"


# --- format_node_report ---

class TestFormatNodeReport:
    def test_contains_sections(self):
        report = format_node_report(
            node_name="node-a",
            snr_name="node-a-abc12",
            strategy="OutOfServiceTaint",
            template_name="template",
            state_table=[{"time": "19:12:15", "phase": "Pre-Reboot-Completed",
                          "processing": "True", "succeeded": "Unknown", "reason": "RemediationStarted"}],
            timeline=[Event(datetime(2026, 1, 1, 19, 9, 46, tzinfo=timezone.utc), "SNR log", "node-a", "SNR validate create")],
            durations=[Duration("Test interval", datetime(2026, 1, 1, 19, 0, tzinfo=timezone.utc),
                                datetime(2026, 1, 1, 19, 5, tzinfo=timezone.utc))],
            notable=["Test note"],
        )
        assert "## Node: node-a" in report
        assert "## SNR CR: node-a-abc12" in report
        assert "SNR Object State" in report
        assert "Correlated Timeline" in report
        assert "Key Durations" in report
        assert "Notable Observations" in report
        assert "Pre-Reboot-Completed" in report
        assert "5m00s" in report
        assert "19:09:46.000" in report


# --- Integration: run() ---

class TestRunIntegration:
    def test_full_pipeline(self, test_dir):
        output = run(str(test_dir))
        assert "node-a" in output
        assert "Pre-Reboot-Completed" in output
        assert "Fencing-Completed" in output
        assert "Correlated Timeline" in output
        assert "Key Durations" in output

    def test_node_filter(self, test_dir):
        output = run(str(test_dir), node_filter="node-a")
        assert "node-a" in output

    def test_node_filter_no_match(self, test_dir):
        output = run(str(test_dir), node_filter="nonexistent")
        assert "No nodes matching" in output

    def test_empty_dir(self, tmp_path):
        output = run(str(tmp_path))
        assert "No SNR yaml" in output

    def test_durations_present(self, test_dir):
        output = run(str(test_dir))
        assert "SNR created → assumed rebooted" in output
        assert "Total remediation" in output

    def test_race_condition_detected(self, test_dir):
        output = run(str(test_dir))
        assert "Race at cleanup" in output


# --- Integration: run against real data ---

class TestRunRealData:
    """Run against actual captured data if available in project dir."""

    @pytest.fixture
    def real_dir(self):
        project_dir = os.path.dirname(os.path.abspath(__file__))
        yamls = [f for f in os.listdir(project_dir) if f.startswith("oc_g_snr.") and f.endswith(".yaml")]
        if not yamls:
            pytest.skip("Real data not available")
        return project_dir

    def test_real_data_runs(self, real_dir):
        output = run(real_dir, node_filter="f03-h06")
        assert "f03-h06-000-r640" in output

    def test_real_data_state_table(self, real_dir):
        output = run(real_dir, node_filter="f03-h06")
        assert "Pre-Reboot-Completed" in output
        assert "Fencing-Completed" in output
        assert "SNR deleted" in output

    def test_real_data_durations(self, real_dir):
        output = run(real_dir, node_filter="f03-h06")
        assert "5m01s" in output

    def test_real_data_notable(self, real_dir):
        output = run(real_dir, node_filter="f03-h06")
        assert "Race at cleanup" in output
        assert "outofservicetaint" in output
