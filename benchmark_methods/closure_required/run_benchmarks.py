"""Compatibility entry point for the baseline closure-required benchmark."""

from pathlib import Path
import runpy
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))
runpy.run_path(str(REPOSITORY_ROOT / "run_goal_count_benchmarks.py"), run_name="__main__")
