# MulVAL 攻击图上的成本收益型 Stackelberg 博弈建模说明

本文档用于解释当前代码中 MIP 约束、核心算法流程以及 Stackelberg 博弈语义。对应主要代码文件为：

```text
build_mulval_game_config.py
solve_mulval_reachability_stackelberg.py
```

其中 `build_mulval_game_config.py` 用于从 MulVAL 攻击图 CSV 生成博弈参数配置文件，`solve_mulval_reachability_stackelberg.py` 用于建立并求解成本收益型 Stackelberg 博弈模型。

---

## 1. 问题背景

MulVAL 生成的攻击图可以被看作一个 AND/OR 依赖图。图中节点主要分为三类：

```text
LEAF 节点：
  系统初始事实，例如漏洞存在、网络连通性、服务信息、攻击者位置等。

AND 节点：
  攻击规则节点，表示一次攻击动作或推理规则成立需要同时满足多个前提。

OR 节点：
  权限、可达性或攻击状态节点，表示只要存在一种攻击规则可以推出该状态，则该状态成立。
```

当前代码采用的边方向为：

```text
结论节点 -> 前提节点
```

例如：

```text
OR 权限节点 -> AND 攻击规则节点
AND 攻击规则节点 -> LEAF/OR 前提节点
```

该方向与代码中读取 `ARCS.CSV` 后的 `outgoing[src].append(dst)` 保持一致。

---

## 2. 博弈参与者与策略空间

该模型描述一个两阶段 Stackelberg 攻防博弈。

第一阶段，防御者作为领导者，先选择一组防御动作：

```text
防御者策略 = 选择若干可防御的 LEAF 节点进行关闭、修复、过滤、加固或隔离
```

第二阶段，攻击者作为跟随者，观察防御者已经采取的防御动作，然后选择：

```text
攻击某个目标节点
或者
选择空攻击 empty
```

需要强调的是，当前模型不枚举攻击路径。攻击者的动作不是“选择一条完整路径”，而是：

```text
选择最终攻击目标
```

攻击某个目标所需的最小攻击成本由 MIP 在攻击图内部隐式计算。

---

## 3. 输入文件

模型使用三个核心输入文件：

```text
VERTICES.CSV
ARCS.CSV
mulval_game_config.json
```

### 3.1 VERTICES.CSV

顶点文件格式为：

```text
id,label,type,score
```

例如：

```text
1,execCode(plc1,root),OR,0.0219
2,RULE 2 (remote exploit of a server program),AND,0.0219
27,networkServiceInfo(historian,http_server,tcp,80,user),LEAF,0.8
```

其中：

```text
id:
  节点编号

label:
  节点语义标签

type:
  节点类型，取值为 OR、AND 或 LEAF

score:
  可选分值，可用于攻击成本来源
```

### 3.2 ARCS.CSV

边文件格式为：

```text
source,target
```

语义为：

```text
source 依赖 target
```

也就是：

```text
结论 -> 前提
```

### 3.3 mulval_game_config.json

配置文件保存博弈参数，例如：

```text
目标收益 reward
目标损失 loss
攻击成本 attack_cost
防御成本 defense_cost
节点是否可防御 defendable
防御预算 budget
强/弱 Stackelberg 打平规则 tie_breaking
```

典型结构如下：

```json
{
  "defaults": {
    "defendable_mode": "vul_hacl",
    "goal_reward": 100.0,
    "goal_loss": 100.0,
    "defense_cost": 1.0,
    "budget": null,
    "attack_cost_source": "constant",
    "action_attack_cost": 1.0,
    "leaf_attack_cost": 0.0,
    "cost_big_m": null,
    "tie_breaking": "strong",
    "tie_epsilon": 0.000001
  },
  "goals": [
    {
      "id": 1,
      "label": "execCode(plc1,root)",
      "enabled": true,
      "reward": 100.0,
      "loss": 600.0
    }
  ],
  "nodes": [
    {
      "id": 27,
      "type": "LEAF",
      "label": "networkServiceInfo(...)",
      "attack_cost": 0.0,
      "defendable": true,
      "defense_cost": 1.0
    }
  ]
}
```

---

## 4. 决策变量

设攻击图节点集合为：

```text
V
```

目标节点集合为：

```text
G
```

可防御 LEAF 节点集合为：

```text
D
```

代码中主要使用以下变量。

### 4.1 节点可达变量

```text
x_i = 1 表示节点 i 在防御后仍然可达或成立
x_i = 0 表示节点 i 在防御后不可达或不成立
```

其中：

```text
i 属于 V
```

### 4.2 防御变量

```text
d_i = 1 表示防御者防御了 LEAF 节点 i
d_i = 0 表示防御者没有防御 LEAF 节点 i
```

其中：

```text
i 属于 D
```

防御动作只作用于被允许防御的 LEAF 节点，例如漏洞节点 `vulExists(...)` 或网络连通性节点 `hacl(...)`。

### 4.3 最小攻击成本变量

```text
c_i = 到达节点 i 的最小攻击推导成本
```

该变量是当前模型避免枚举攻击路径的关键。它不记录完整路径，而是在 AND/OR 图结构上通过约束递推得到。

### 4.4 攻击者响应变量

```text
y_empty = 1 表示攻击者选择空攻击
y_g = 1 表示攻击者选择攻击目标 g
```

其中：

```text
g 属于 G
```

攻击者最终只能选择一个响应：

```text
要么 empty
要么某个目标 g
```

---

## 5. LEAF 节点约束

LEAF 节点表示初始事实。对于可防御 LEAF 节点，代码使用如下约束：

```text
x_i + d_i = 1
```

含义是：

```text
如果防御者防御节点 i，则 d_i = 1，x_i = 0
如果防御者不防御节点 i，则 d_i = 0，x_i = 1
```

也就是说，可防御事实默认成立，但可以被防御动作关闭。

对于不可防御 LEAF 节点，例如 `attackerLocated(internet)`，代码固定为：

```text
x_i = 1
```

含义是：

```text
该初始事实始终成立，防御者不能关闭它
```

---

## 6. AND 节点可达性约束

AND 节点表示一个攻击规则。若 AND 节点为 `e`，其前提节点集合为：

```text
child(e)
```

AND 节点成立当且仅当所有前提节点都成立。

代码中使用两类线性约束表达该语义。

第一类约束：

```text
x_e <= x_j
```

对每个前提节点 `j` 都添加一条。

含义是：

```text
只要 AND 节点 e 成立，则每个前提节点 j 都必须成立
```

第二类约束：

```text
x_e >= 所有 x_j 之和 - (前提数量 - 1)
```

含义是：

```text
如果所有前提节点都成立，则 AND 节点 e 必须成立
```

因此，AND 节点被精确编码为：

```text
x_e = 所有前提节点的逻辑与
```

---

## 7. OR 节点可达性约束

OR 节点表示某种权限、访问能力或攻击状态。若 OR 节点为 `p`，其子节点集合为：

```text
child(p)
```

OR 节点成立当且仅当至少存在一个子节点成立。

代码中使用两类约束。

第一类约束：

```text
x_p >= x_j
```

对每个子节点 `j` 都添加一条。

含义是：

```text
只要某个子节点 j 成立，则 OR 节点 p 成立
```

第二类约束：

```text
x_p <= 所有 x_j 之和
```

含义是：

```text
如果 OR 节点 p 成立，则至少有一个子节点成立
```

因此，OR 节点被精确编码为：

```text
x_p = 所有子节点的逻辑或
```

---

## 8. 最小攻击成本约束

当前模型的核心思想是：

```text
不枚举攻击路径，而是为每个节点计算一个最小攻击推导成本
```

节点成本变量为：

```text
c_i
```

如果节点不可达，则其成本被约束为 0：

```text
c_i <= BigM * x_i
```

因此：

```text
x_i = 0 时，c_i = 0
x_i = 1 时，c_i 可以表示真实最小攻击成本
```

### 8.1 LEAF 节点成本

对于 LEAF 节点：

```text
c_i = attack_cost_i * x_i
```

含义是：

```text
如果 LEAF 节点可用，则使用该事实需要 attack_cost_i
如果 LEAF 节点不可用，则成本为 0
```

默认情况下：

```text
leaf_attack_cost = 0
```

也就是说，初始事实本身不增加攻击成本。

### 8.2 AND 节点成本

对于 AND 节点 `e`：

```text
c_e = attack_cost_e + 所有前提节点成本之和
```

代码中用 BigM 形式写成：

```text
c_e >= attack_cost_e + 所有 c_j 之和 - BigM * (1 - x_e)
c_e <= attack_cost_e + 所有 c_j 之和 + BigM * (1 - x_e)
```

当 `x_e = 1` 时，上述约束退化为：

```text
c_e = attack_cost_e + 所有 c_j 之和
```

当 `x_e = 0` 时，该等式被 BigM 放松，同时 `c_e <= BigM * x_e` 会把 `c_e` 压为 0。

### 8.3 OR 节点成本

OR 节点代表多条攻击推导路径的选择。它的最小成本应为：

```text
c_p = 所有可达子节点成本中的最小值
```

代码通过选择变量实现这一点。对于 OR 节点 `p` 的每个子节点 `j`，引入：

```text
s_pj = 1 表示 OR 节点 p 选择子节点 j 作为最小成本推导
```

约束包括：

```text
s_pj <= x_j
```

含义是：

```text
只能选择可达的子节点
```

如果 OR 节点可达，则必须选择一个子节点：

```text
所有 s_pj 之和 = x_p
```

如果选择了子节点 `j`，则：

```text
c_p = c_j
```

代码使用 BigM 写成：

```text
c_p >= c_j - BigM * (1 - s_pj)
c_p <= c_j + BigM * (1 - s_pj)
```

同时，对所有可达子节点添加：

```text
c_p <= c_j + BigM * (1 - x_j)
```

这保证 OR 节点成本不会高于任何可达子节点成本。结合选择变量，OR 节点最终表达为：

```text
c_p = min{c_j | j 是 p 的可达子节点}
```

---

## 9. 攻击者效用

攻击者对目标 `g` 的净收益定义为：

```text
attacker_utility_g = reward_g - c_g
```

其中：

```text
reward_g:
  攻击者攻下目标 g 后获得的收益

c_g:
  防御后到达目标 g 的最小攻击成本
```

空攻击的收益定义为：

```text
attacker_utility_empty = 0
```

因此，攻击者选择规则为：

```text
如果所有目标的 attacker_utility_g <= 0，则选择 empty
否则选择 attacker_utility_g 最大的目标
```

---

## 10. 攻击者响应约束

攻击者必须选择且只选择一个响应：

```text
y_empty + 所有 y_g 之和 = 1
```

攻击者只能攻击可达目标：

```text
y_g <= x_g
```

若攻击者选择目标 `g`，则目标 `g` 的攻击者效用必须不小于其他目标的效用，也不小于空攻击效用。

对任意两个目标 `g` 和 `h`：

```text
如果 y_g = 1，则：
reward_g - c_g >= reward_h * x_h - c_h
```

代码使用 BigM 写成：

```text
reward_g - c_g >= reward_h * x_h - c_h - BigM * (1 - y_g)
```

目标 `g` 还必须不差于 empty：

```text
如果 y_g = 1，则：
reward_g - c_g >= 0
```

代码中写成：

```text
reward_g - c_g >= -BigM * (1 - y_g)
```

若攻击者选择 empty，则所有目标的效用必须不大于 0：

```text
如果 y_empty = 1，则：
0 >= reward_h * x_h - c_h
```

代码中写成：

```text
0 >= reward_h * x_h - c_h - BigM * (1 - y_empty)
```

---

## 11. 强 Stackelberg 与弱 Stackelberg

Stackelberg 博弈中，攻击者可能存在多个最优响应。例如两个目标对攻击者的净收益相同：

```text
目标 1 攻击者净收益 = 90
目标 55 攻击者净收益 = 90
```

但它们给防御者造成的损失不同：

```text
目标 1 防御者损失 = 600
目标 55 防御者损失 = 100
```

此时需要定义攻击者在打平时如何选择。

### 11.1 强 Stackelberg

强 Stackelberg 假设：

```text
如果攻击者存在多个最优响应，则攻击者选择对防御者最有利的响应
```

在上述例子中，攻击者会选择：

```text
目标 55
```

因为它对防御者造成的损失更低。

代码中，当 `tie_breaking = strong` 时，不对攻击者效用添加额外扰动。由于 `y_g` 变量直接进入防御者目标函数，MIP 在攻击者无差异时会选择防御者损失较小的响应。

### 11.2 弱或悲观 Stackelberg

弱 Stackelberg 在当前代码中按悲观打平规则处理：

```text
如果攻击者存在多个最优响应，则攻击者选择对防御者最不利的响应
```

在上述例子中，攻击者会选择：

```text
目标 1
```

因为它对防御者造成的损失更高。

代码中通过一个很小的扰动项实现：

```text
攻击者用于比较的效用 = 原攻击者净收益 + tie_epsilon * 防御者损失
```

其中：

```text
tie_epsilon 默认等于 0.000001
```

该项应足够小，使其只用于打破平局，而不改变攻击者对主要收益差异的判断。

运行弱 Stackelberg 时使用：

```bash
python solve_mulval_reachability_stackelberg.py \
  --vertices VERTICES.CSV \
  --arcs ARCS.CSV \
  --config mulval_game_config.json \
  --tie-breaking weak
```

---

## 12. 防御者目标函数

防御者的目标是最小化：

```text
防御成本 + 攻击者最终选择目标造成的损失
```

具体为：

```text
minimize:
  所有 defense_cost_i * d_i 之和
  +
  所有 loss_g * y_g 之和
```

其中：

```text
defense_cost_i:
  防御节点 i 的成本

loss_g:
  攻击者攻下目标 g 后防御者承受的损失
```

如果攻击者选择 empty，则所有 `y_g = 0`，防御者不承受攻击损失，只承受防御成本。

---

## 13. 防御预算约束

如果配置文件或命令行设置了防御预算 `budget`，则添加：

```text
所有 defense_cost_i * d_i 之和 <= budget
```

如果 `budget = null`，则不添加预算约束。

---

## 14. 可防御节点规则

代码支持四种可防御模式：

```text
all:
  所有 LEAF 节点都可防御，除了 attackerLocated(...)

vul:
  只有 vulExists(...) 节点可防御

hacl:
  只有 hacl(...) 节点可防御

vul_hacl:
  只有 vulExists(...) 和 hacl(...) 节点可防御
```

也可以在 JSON 中逐节点指定：

```json
{
  "id": 30,
  "defendable": true,
  "defense_cost": 5.0
}
```

如果命令行显式传入：

```bash
--defendable vul
```

则优先按照命令行规则计算可防御节点；否则使用 JSON 中的逐节点 `defendable` 设置。

---

## 15. 核心算法流程

当前求解流程可以概括如下。

### 15.1 配置生成阶段

由 `build_mulval_game_config.py` 完成。

算法流程：

```text
输入：
  VERTICES.CSV
  ARCS.CSV

步骤：
  1. 读取所有节点和边
  2. 统计 OR、AND、LEAF 节点数量
  3. 自动识别目标节点，或读取用户指定目标
  4. 根据 defendable_mode 标记哪些 LEAF 节点可防御
  5. 为目标写入默认 reward 和 loss
  6. 为节点写入默认 attack_cost、defense_cost、defendable
  7. 输出 mulval_game_config.json
```

生成配置命令示例：

```bash
python build_mulval_game_config.py \
  --vertices VERTICES.CSV \
  --arcs ARCS.CSV \
  --out mulval_game_config.json \
  --defendable vul_hacl \
  --goals 1,55
```

### 15.2 博弈求解阶段

由 `solve_mulval_reachability_stackelberg.py` 完成。

算法流程：

```text
输入：
  VERTICES.CSV
  ARCS.CSV
  mulval_game_config.json

步骤：
  1. 读取攻击图节点和边
  2. 读取博弈配置 JSON
  3. 确定目标集合 G
  4. 确定可防御节点集合 D
  5. 创建 MIP 模型
  6. 创建 x_i、d_i、c_i、y_empty、y_g 等变量
  7. 添加 LEAF 节点约束
  8. 添加 AND/OR 可达性约束
  9. 添加最小攻击成本约束
  10. 添加攻击者最优响应约束
  11. 添加防御预算约束
  12. 设置防御者目标函数
  13. 调用 PySCIPOpt/SCIP 求解
  14. 输出均衡防御策略、攻击者响应、可达目标、目标函数值
```

---

## 16. 为什么不枚举攻击路径

传统路径枚举方法会显式生成：

```text
攻击路径 1
攻击路径 2
攻击路径 3
...
```

在大规模攻击图中，路径数量可能指数增长，导致不可扩展。

当前模型不枚举路径，而是通过：

```text
AND 节点成本累加
OR 节点成本取最小
```

隐式计算到达每个目标的最小攻击成本。

因此，攻击者响应只需要比较：

```text
reward_g - c_g
```

而不需要列出每条具体路径。

这种思想等价于：

```text
攻击者在防御者给定策略下，自动选择一条最小综合成本的攻击推导
```

但该推导路径没有被显式枚举。

---

## 17. 结果字段解释

求解结果 JSON 中常见字段如下。

```text
status:
  求解状态，例如 optimal

solution_concept:
  解概念，例如 cost-sensitive pure Strong Stackelberg equilibrium

selected_defenses:
  防御者选择的防御节点集合

reachable_goals:
  防御后仍然可达的目标，以及每个目标的最小攻击成本和攻击者净收益

attacker_response:
  攻击者最优响应，可能是 empty，也可能是 attack_goal

attacker_utility:
  攻击者最终获得的净收益

defender_utility:
  防御者效用，等于目标函数值的相反数

objective_cost_form:
  防御成本 + 攻击者最终选择目标造成的损失
```

例如：

```json
{
  "selected_defenses": [],
  "attacker_response": {
    "type": "attack_goal",
    "goal": {
      "id": 55,
      "label": "execCode(plc2,user)",
      "attacker_net_utility": 90.0
    }
  },
  "objective_cost_form": 100.0
}
```

表示：

```text
防御者最优策略是不防御；
攻击者最优响应是攻击目标 55；
防御者总成本为 100。
```

---

## 18. 强 Stackelberg 下攻防双方都非空的条件

若希望出现：

```text
selected_defenses 非空
attacker_response 不是 empty
```

通常需要满足以下条件：

```text
1. 高损失目标对攻击者具有严格更高收益；
2. 防御者可以通过部分防御改变攻击者目标选择；
3. 防御者无法低成本完全阻断所有正收益攻击；
4. 防御后仍存在至少一个目标使攻击者净收益大于 0。
```

例如：

```text
不防御时：
  目标 1 攻击者净收益 = 190，防御者损失 = 600
  目标 55 攻击者净收益 = 90，防御者损失 = 100

防御某些节点后：
  目标 1 攻击者净收益下降到 70
  目标 55 攻击者净收益仍为 90

于是：
  防御者会防御部分节点
  攻击者会转而攻击目标 55
```

此时均衡表现为：

```text
防御者策略非空
攻击者策略非空
```

---

## 19. 概率的引入方式

当前代码主要使用成本收益建模。若要引入攻击成功概率，推荐把概率转换为风险成本：

```text
effective_attack_cost_i = base_attack_cost_i + risk_weight * (-ln(success_prob_i))
```

这样多步攻击路径的成功概率乘法可以转化为成本加法：

```text
路径成功概率 = p1 * p2 * p3

负对数风险成本 =
  -ln(p1) + -ln(p2) + -ln(p3)
```

这可以保持 MIP 仍然是线性模型，适合大规模攻击图。

若使用精确期望收益：

```text
攻击者期望收益 = reward * success_probability - attack_cost
```

则 AND/OR 概率传播会涉及乘法，容易变成非线性模型，不利于大规模求解。

---

## 20. 模型局限性

当前模型有以下假设：

```text
1. 攻击者最终只选择一个目标，而不是混合策略；
2. 防御者使用纯策略，而不是概率混合防御；
3. 攻击路径不显式输出，只输出目标的最小攻击成本；
4. OR 节点以最小攻击成本表示攻击者偏好；
5. 弱 Stackelberg 通过极小扰动近似实现悲观打平；
6. 若需要精确路径级概率、混合策略或多攻击者行为，需要进一步扩展模型。
```

这些假设的优点是：

```text
模型保持线性；
不枚举攻击路径；
适合较大规模 MulVAL 攻击图；
可以直接使用 SCIP/PySCIPOpt 求解。
```

---

## 21. 总结

当前代码实现的是一个基于 MulVAL AND/OR 攻击图的成本收益型 Stackelberg 博弈模型。

其核心思想可以概括为：

```text
防御者先选择防御哪些 LEAF 条件；
攻击图根据 AND/OR 规则传播可达性；
MIP 隐式计算每个目标的最小攻击成本；
攻击者选择净收益最大的目标，或者选择 empty；
防御者预测攻击者响应后，最小化防御成本和攻击损失。
```

该模型的关键优势是：

```text
不枚举攻击路径；
可处理大规模攻击图；
能表达攻击收益、攻击成本、防御成本、目标损失；
能切换强 Stackelberg 和弱/悲观 Stackelberg 打平规则。
```

