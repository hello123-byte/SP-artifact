# 双并行攻击路径测试图

按论文和可视化采用的“前提 -> 结论”方向：

```text
attackerLocated + vul A -> RULE A --\
                                     OR goal
attackerLocated + vul B -> RULE B --/
```

任意一条路径成功都能到达目标。只防御一个漏洞时，攻击者会切换到另一条路径；必须连续防御漏洞 `2` 和 `3` 才能阻断目标。

不使用 warm start：

```bash
python3 solve_mulval__stackelberg_main.py \
  --vertices parallel_attack_test_graph/VERTICES.CSV \
  --arcs parallel_attack_test_graph/ARCS.CSV \
  --goals 6 --defendable vul --target-closure \
  --attack-cost-source score --default-reward 100 --default-loss 100 \
  --solver scip --mip-gap 0 --time-limit 30 \
  --out /tmp/parallel_cold.json
```

使用关键路径 warm start：

```bash
python3 solve_mulval__stackelberg_main.py \
  --vertices parallel_attack_test_graph/VERTICES.CSV \
  --arcs parallel_attack_test_graph/ARCS.CSV \
  --goals 6 --defendable vul --target-closure \
  --attack-cost-source score --default-reward 100 --default-loss 100 \
  --warm-start-key-path \
  --solver scip --mip-gap 0 --time-limit 30 \
  --out /tmp/parallel_warm.json
```
