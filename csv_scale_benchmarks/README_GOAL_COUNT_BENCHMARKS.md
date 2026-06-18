# Goal Count Benchmarks

This folder keeps the CSV graph size fixed and varies only the number of target
goals used by the Stackelberg solver.

Folders:

```text
scale_10k/goal_sets      1, 2, 4, 8, 10 goals
scale_100k/goal_sets     1, 5, 10, 25, 50, 100 goals
scale_1m/goal_sets       1, 10, 50, 100, 500, 1000, 5000, 10000 goals
```

Each `goals_N.txt` file contains a comma-separated goal ID list that can be
passed directly to `solve_mulval__stackelberg_main.py`:

```powershell
$goals = (Get-Content .\csv_scale_benchmarks\scale_100k\goal_sets\goals_25.txt -Raw).Trim()
python .\solve_mulval__stackelberg_main.py `
  --vertices .\csv_scale_benchmarks\scale_100k\VERTICES.CSV `
  --arcs .\csv_scale_benchmarks\scale_100k\ARCS.CSV `
  --goals $goals `
  --defendable vul `
  --target-closure `
  --time-limit 100 `
  --out .\csv_scale_benchmarks\results\scale_100k_goals_25.json
```

You can also run the prepared PowerShell batch:

```powershell
.\csv_scale_benchmarks\run_goal_count_benchmarks.ps1
```

For million-scale cases, using `--target-closure` is strongly recommended.
Generating full config JSON files for every goal count is intentionally avoided
because those files can be much larger than the CSV timing inputs.
