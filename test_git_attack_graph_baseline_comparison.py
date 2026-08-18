import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "benchmark_methods" / "git_attack_graph_baseline_comparison" / "run_benchmarks.py"
SPEC = importlib.util.spec_from_file_location("git_baseline_comparison", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

sys.path.insert(0, str(ROOT / "baselines"))
from full_path_enumeration_baseline import GoalPath, exact_path_cover


def test_compute_budget_uses_floor_and_minimum_one():
    assert MODULE.compute_budget(4, None, 0.4) == 1.0
    assert MODULE.compute_budget(9, None, 0.4) == 3.0
    assert MODULE.compute_budget(152, None, 0.4) == 60.0
    assert MODULE.compute_budget(4, 2.5, 0.4) == 2.5


def test_hard_timeout_marks_and_stops_process(tmp_path):
    returncode, wall_seconds, timed_out = MODULE.run_with_hard_timeout(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        tmp_path / "timeout.log",
        timeout_seconds=0.02,
        termination_grace_seconds=0.2,
    )
    assert timed_out is True
    assert returncode is None
    assert wall_seconds < 1.0


def test_random_effectiveness_uses_mean_not_best():
    result = {
        "empty_objective_cost_form": 100.0,
        "objective_mean": 40.0,
        "objective_cost_form": 10.0,
        "benefit_score": 0.9,
    }
    assert MODULE.mean_benefit(result) == 0.6


def make_attack_path(*vulnerabilities):
    return GoalPath(
        goal=1,
        leaves=frozenset(vulnerabilities),
        vuln_leaves=frozenset(vulnerabilities),
        cost=1.0,
        reward=1000.0,
        loss=1000.0,
        attacker_net_utility=999.0,
    )


def test_exact_path_cover_selects_global_minimum():
    from types import SimpleNamespace

    problem = SimpleNamespace(
        defendable=[1, 2, 3],
        defense_costs={},
        default_defense_cost=1.0,
    )
    paths = [make_attack_path(1, 2), make_attack_path(2, 3)]
    selected, stats = exact_path_cover(problem, paths, budget=2.0)
    assert selected == {2}
    assert stats["exact_cover"] is True
    assert stats["blocking_strategy_found"] is True


def test_exact_path_cover_returns_empty_when_budget_is_insufficient():
    from types import SimpleNamespace

    problem = SimpleNamespace(
        defendable=[1, 2],
        defense_costs={},
        default_defense_cost=1.0,
    )
    paths = [make_attack_path(1), make_attack_path(2)]
    selected, stats = exact_path_cover(problem, paths, budget=1.0)
    assert selected == set()
    assert stats["blocking_strategy_found"] is False


def test_exact_path_cover_minimizes_cost_before_cardinality():
    from types import SimpleNamespace

    problem = SimpleNamespace(
        defendable=[1, 2, 3],
        defense_costs={1: 5.0, 2: 1.0, 3: 1.0},
        default_defense_cost=1.0,
    )
    paths = [make_attack_path(1, 2), make_attack_path(1, 3)]
    selected, _ = exact_path_cover(problem, paths, budget=5.0)
    assert selected == {2, 3}


def test_effectiveness_table_formats_scores_and_timeout(tmp_path):
    rows = [
        {"dataset": "S1", "method": "empty", "budget": 1.0, "status": "ok", "effectiveness_score": 0.0},
        {"dataset": "S1", "method": "random", "budget": 1.0, "status": "ok", "effectiveness_score": 0.719},
        {"dataset": "S1", "method": "path_enum", "budget": 1.0, "status": "timeout", "effectiveness_score": None},
        {"dataset": "S1", "method": "stackelberg", "budget": 1.0, "status": "optimal", "effectiveness_score": 0.999},
    ]
    output = tmp_path / "table.csv"
    MODULE.write_effectiveness_table(output, rows)
    text = output.read_text(encoding="utf-8-sig")
    assert "数据集,预算,Empty,Random,Path enumeration,GA,Our" in text
    assert "S1,1,0.000,0.719,timeout,,0.999" in text


def test_strategy_table_lists_ids_labels_and_random_scope(tmp_path):
    rows = [
        {
            "dataset": "S1",
            "method": "random",
            "display_name": "Random",
            "status": "ok",
            "effectiveness_score": 0.719,
            "best_benefit_score": 0.999,
            "strategy_scope": "best_of_random_trials",
            "selected_defense_count": 1,
            "defense_cost": 1.0,
            "selected_defense_ids": "16",
            "selected_defense_labels": "ttpExists(host,cve)",
        },
        {
            "dataset": "S300",
            "method": "path_enum",
            "display_name": "Path enumeration",
            "status": "timeout",
            "effectiveness_score": None,
            "best_benefit_score": None,
            "strategy_scope": "not_completed",
            "selected_defense_count": 0,
            "defense_cost": None,
            "selected_defense_ids": "",
            "selected_defense_labels": "",
        },
    ]
    output = tmp_path / "strategies.csv"
    MODULE.write_strategy_table(output, rows)
    text = output.read_text(encoding="utf-8-sig")
    assert "Random,ok,0.719,0.999" in text
    assert '16,"ttpExists(host,cve)"' in text
    assert "Path enumeration,timeout,timeout,timeout,未完成" in text
