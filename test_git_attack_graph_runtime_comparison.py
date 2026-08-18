import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "benchmark_methods" / "git_attack_graph_runtime_comparison" / "run_benchmarks.py"
SPEC = importlib.util.spec_from_file_location("git_runtime_comparison", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def make_row(repetition, status, wall):
    return {
        "repetition": repetition,
        "dataset": "S1",
        "method": "stackelberg",
        "display_name": "Our",
        "status": status,
        "timed_out": status == "timeout",
        "time_limit_seconds": 30.0,
        "wall_seconds": wall,
        "algorithm_seconds": wall,
        "node_count": 35,
        "arc_count": 37,
        "goal_count": 2,
        "budget": 1.0,
    }


def test_runtime_summary_reports_median_and_std():
    summary = MODULE.summarize_group([
        make_row(1, "optimal", 0.1),
        make_row(2, "optimal", 0.2),
        make_row(3, "optimal", 0.3),
    ])
    assert summary["status"] == "completed"
    assert summary["completed_count"] == 3
    assert summary["timeout_count"] == 0
    assert summary["wall_median_seconds"] == 0.2
    assert summary["wall_std_seconds"] > 0


def test_runtime_summary_keeps_timeout_separate():
    summary = MODULE.summarize_group([
        make_row(1, "timeout", 30.0),
        make_row(2, "timeout", 30.0),
        make_row(3, "timeout", 30.0),
    ])
    assert summary["status"] == "timeout"
    assert summary["completed_count"] == 0
    assert summary["timeout_count"] == 3
    assert summary["wall_median_seconds"] is None
    assert MODULE.runtime_cell(summary) == "timeout"


def test_runtime_table_marks_partial_timeout():
    summary = MODULE.summarize_group([
        make_row(1, "optimal", 0.2),
        make_row(2, "timeout", 30.0),
    ])
    assert summary["status"] == "partial_timeout"
    assert MODULE.runtime_cell(summary) == "0.200000 (1/2 timeout)"
