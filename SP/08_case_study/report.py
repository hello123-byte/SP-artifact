"""Publication outputs for multiple cost scenarios, using saved numeric results."""
from __future__ import annotations
import csv, hashlib, json, re, subprocess, time
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle, Ellipse
from case_data import TOPOLOGY

HERE=Path(__file__).resolve().parent
BLUE='#2864a0';RED='#bb4444';GREEN='#27846b';GRAY='#8795a4';ORANGE='#ca8124'
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,
    'axes.spines.right':False,'pdf.fonttype':42,'ps.fonttype':42,'svg.fonttype':'none'})


def read(path):return json.loads((HERE/path).read_text())
def num(x):return '—' if x is None else f'{x:g}'
def response(row):
    if row['outcome']=='blocked':return '放弃（目标不可达）'
    if row['outcome']=='deterred':return '放弃（净收益不足）'
    return row['attacker_response']


def save(fig,name):
    for ext in ('pdf','svg','png'):
        fig.savefig(HERE/'figures'/f'{name}.{ext}',bbox_inches='tight',dpi=200)
    plt.close(fig)


def stats(rows,key):
    q1,median,q3=np.quantile([r[key] for r in rows],[.25,.5,.75])
    return dict(median=float(median),q1=float(q1),q3=float(q3),n=len(rows))


def patch_label(row,mapping,short=False):
    return ' + '.join(mapping[c]['service'] if short else c for c in row['patched_cves']) or ('None' if short else '无')


def utility_cell(goal):
    return f"{goal['reward']:g}−{goal['min_attack_cost']:g}={goal['utility']:g}" if goal['reachable'] else '不可达'


def network_panel(case,row,ax,title,mapping,topology=False):
    positions={'internet':(0,1),'h1':(1.4,1.65),'h2':(1.4,.35),
               'h3':(2.85,1),'h4':(4.3,1.65),'h5':(4.3,.35),'h6':(5.75,.35)}
    patched={mapping[c]['host'] for c in row.get('patched_cves',[])}
    alive=set(row.get('reachable_hosts',positions))|{'internet'}
    action_hosts={i:m['host'] for m in mapping.values() for i in m['actions']}
    route=['internet']+[action_hosts[i] for i in reversed(row.get('attack_actions',[]))]
    chosen_path=set(zip(route,route[1:]))
    radius=.19
    for a,b,_ in TOPOLOGY:
        x1,y1=positions[a];x2,y2=positions[b]
        dx,dy=x2-x1,y2-y1
        distance=(dx*dx+dy*dy)**.5
        inset=radius+.04
        blocked=a not in alive or b not in alive
        color=GRAY if blocked else (RED if (a,b) in chosen_path else BLUE)
        ax.add_patch(FancyArrowPatch((x1+dx/distance*inset,y1+dy/distance*inset),
            (x2-dx/distance*inset,y2-dy/distance*inset),arrowstyle='-|>',
            mutation_scale=13,linewidth=2 if (a,b) in chosen_path else 1.4,
            color=color,linestyle='--' if blocked else '-'))
    for host,(x,y) in positions.items():
        blocked=host not in alive
        fill,border=('#f1f3f5',GRAY) if blocked else ('#eaf1fa',BLUE)
        if host in ('h4','h6') and not blocked:fill,border='#e8f3ee',GREEN
        if host in patched:fill,border='#ffe3db',ORANGE
        ax.add_patch(Circle((x,y),radius,facecolor=fill,edgecolor=border,linewidth=2))
        ax.text(x,y,'A' if host=='internet' else host,ha='center',va='center',
                fontsize=11,weight='bold',color='#253e56')
        label='Attacker' if host=='internet' else ('Target 1' if host=='h4' else 'Target 2' if host=='h6' else '')
        if host in patched:label='Patched'
        if label:ax.text(x,y-.34,label,ha='center',va='center',fontsize=10,color=border)
    ax.set(xlim=(-.5,6.2),ylim=(-.3,2.1),aspect='equal');ax.axis('off')
    ax.set_title(title,loc='left',fontweight='bold',fontsize=11)


def component_topology(case):
    """Vector device illustration of the logical topology; export at any scale."""
    fig, ax = plt.subplots(figsize=(16, 7))
    ink = '#253e56'
    positions = {'internet': (1, 3.5), 'h1': (4, 5.2), 'h2': (4, 1.8),
                 'h3': (7.4, 3.5), 'h4': (10.8, 5.2),
                 'h5': (10.8, 1.8), 'h6': (14.2, 1.8)}
    for left, width, label in [(0, 2.3, 'External'), (2.7, 2.6, 'Entry services'),
                               (6, 2.8, 'Application'), (9.4, 6, 'Internal assets')]:
        ax.add_patch(FancyBboxPatch((left, .25), width, 6.5,
            boxstyle='round,pad=0.08', facecolor='#f3f6fa', edgecolor='none', zorder=0))
        ax.text(left + width / 2, 6.4, label, ha='center', fontsize=10, weight='bold', color='#65788c')

    def box(x, y, w, h, color='#e4eef9'):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.04',
            facecolor=color, edgecolor=ink, linewidth=1.7, zorder=3))

    for a, b, port in TOPOLOGY:
        x1, y1 = positions[a]; x2, y2 = positions[b]
        ax.add_patch(FancyArrowPatch((x1+.65, y1), (x2-.7, y2),
            arrowstyle='-|>', mutation_scale=15, linewidth=1.8, color=BLUE, zorder=2))

    vulns = {v['host']: v for v in case['vulnerabilities']}
    for host, (x, y) in positions.items():
        if host == 'internet':
            # Overlapping filled circles form the Internet cloud silhouette.
            for dx, dy, r in [(-.34, 0, .29), (-.08, .23, .38), (.3, .12, .31), (.4, -.06, .23)]:
                ax.add_patch(Circle((x+dx, y+dy), r, facecolor='#dceafa', edgecolor=BLUE, lw=1.5, zorder=3))
            ax.add_patch(Rectangle((x-.36, y-.2), .78, .39, color='#dceafa', zorder=4))
            ax.text(x, y-.83, 'Internet', ha='center', fontsize=11, weight='bold', color='#172b40')
            ax.text(x, y-1.1, 'Attack origin', ha='center', fontsize=10, color='#253e56')
            continue
        if host in ('h1', 'h3'):
            box(x-.43, y-.48, .86, 1.08)
            for offset in (-.22, .08, .38):
                box(x-.32, y+offset, .64, .14, 'white')
                ax.add_patch(Circle((x+.21, y+offset+.07), .025, color=GREEN, zorder=4))
        elif host == 'h2':
            box(x-.6, y-.3, 1.2, .6)
            for dx in (-.42, -.23, -.04):
                ax.add_patch(Rectangle((x+dx, y-.15), .1, .1, color=BLUE, zorder=4))
            ax.plot([x-.4, x-.4], [y+.3, y+.67], color=ink, lw=2)
            ax.plot([x+.4, x+.4], [y+.3, y+.67], color=ink, lw=2)
            ax.text(x, y+.03, 'VPN', ha='center', fontsize=9, weight='bold', color=ink, zorder=4)
        elif host == 'h4':
            ax.add_patch(Rectangle((x-.5, y-.4), 1, .85, facecolor='#dcefe8', edgecolor=ink, lw=1.7, zorder=3))
            for dy in (-.4, -.08, .2, .45):
                ax.add_patch(Ellipse((x, y+dy), 1, .27, facecolor='#dcefe8', edgecolor=ink, lw=1.5, zorder=4))
        elif host == 'h5':
            box(x-.6, y-.24, 1.05, .72)
            ax.add_patch(Rectangle((x-.51, y-.15), .87, .52, facecolor='#c5ddf3', edgecolor='none', zorder=4))
            ax.plot([x-.08, x-.08], [y-.29, y-.5], color=ink, lw=3)
            ax.plot([x-.36, x+.2], [y-.5, y-.5], color=ink, lw=3)
            box(x+.53, y-.45, .3, .94)
        else:
            box(x-.6, y-.38, 1.2, .82, '#dcefe8')
            box(x-.4, y-.18, .45, .38, '#9ccdbd')
            for dx in (.2, .36, .52):
                ax.plot([x+dx, x+dx], [y-.2, y+.23], color=ink, lw=1.4, zorder=4)
            for dx in (-.42, -.21, 0, .21, .42):
                ax.add_patch(Rectangle((x+dx-.035, y+.45), .07, .15, color=ink, zorder=4))
                ax.add_patch(Rectangle((x+dx-.035, y-.55), .07, .15, color=ink, zorder=4))
        v = vulns[host]
        ax.text(x, y-.85, f"{host}  |  {v['service']}", ha='center', fontsize=11, weight='bold', color='#172b40')
        ax.text(x, y-1.14, v['cve'], ha='center', fontsize=10, color='#253e56')
        if host in ('h4', 'h6'):
            ax.text(x, y+.9, 'Target 1' if host=='h4' else 'Target 2', ha='center',
                    fontsize=9, weight='bold', color=GREEN)
    ax.set(xlim=(-.25, 15.7), ylim=(0, 6.9), aspect='equal')
    ax.axis('off')
    save(fig, 'topology')


def network_figures(cases,budgets,counters,mapping):
    lookup={(r['scenario'],r['budget']):r for r in budgets}
    component_topology(cases[0])
    for case in cases:
        ident=case['id']
        if ident=='S1':panels=[('B=0',lookup[ident,0]),('B=15',lookup[ident,15])]
        elif ident=='S2':panels=[(f'B={b}',lookup[ident,b]) for b in (0,5,17)]
        elif ident=='S3':
            adverse=next(r for r in counters if r['scenario']==ident and r['policy']=='patch_redis_only')
            panels=[('B=5 | optimal',lookup[ident,5]),('B=5 | feasible alternative, not optimal',adverse),('B=17 | optimal',lookup[ident,17])]
        else:panels=[('B=0',lookup[ident,0]),('B=4 | both targets remain reachable',lookup[ident,4])]
        fig,axes=plt.subplots(len(panels),1,figsize=(15,3.2*len(panels)))
        for ax,(label,row) in zip(axes,panels):
            outcome=row['attacker_response']
            if row['outcome']=='blocked':outcome='No attack (blocked)'
            if row['outcome']=='deterred':outcome='No attack (unprofitable)'
            title=f"{ident} | {label} | patch={row['defense_cost']:g}; J={row['objective']:g}; response: {outcome}"
            network_panel(case,row,ax,title,mapping)
        fig.text(.08,.008,'Orange: patched node. Green: reachable target. Red arrows: selected attack path. Dashed arrows: blocked propagation.',fontsize=8)
        fig.tight_layout(rect=(0,.025,1,1))
        if ident=='S2':
            fig.savefig(HERE/'figures'/'defense_before_after.png',bbox_inches='tight',dpi=200)
        fig.savefig(HERE/'figures'/f'{ident}_defense.png',bbox_inches='tight',dpi=200)
        plt.close(fig)
    vertices=list(csv.reader((HERE/'graph/VERTICES.CSV').read_text().splitlines()))
    arcs=list(csv.reader((HERE/'graph/ARCS.CSV').read_text().splitlines()))
    lines=['digraph G {','rankdir=LR;','node [fontname="DejaVu Sans",fontsize=10];']
    for ident,label,kind,_ in vertices:
        label=re.sub(r'\b[hH]\d+\b,?','',label).replace(',)',')')
        lines.append(f'{ident} [label={json.dumps(label)},shape={dict(OR="diamond",AND="ellipse",LEAF="box")[kind]}];')
    lines.extend(f'{b} -> {a};' for a,b,_ in arcs);lines.append('}')
    dot=HERE/'figures/attack_graph.dot';dot.write_text('\n'.join(lines)+'\n')
    for ext in ('pdf','svg','png'):subprocess.run(['dot',f'-T{ext}',str(dot),'-o',str(dot.with_suffix('.'+ext))],check=True)


def curves(cases,budgets):
    fig,axes=plt.subplots(2,2,figsize=(12,8.4))
    for ax,case in zip(axes.flat,cases):
        ident=case['id'];rows=[r for r in budgets if r['scenario']==ident]
        limit=int(rows[0]['minimum_blocking_cost'])+5
        shown=[r for r in rows if r['budget']<=limit];x=[r['budget'] for r in shown]
        for target,color in [('Redis',GREEN),('Modicon M221',RED)]:
            gs=[next(g for g in r['goals'] if g['name']==target) for r in shown]
            y=[g['utility'] if g['reachable'] else np.nan for g in gs]
            ax.step(x,y,where='post',label=target,color=color,linewidth=2)
        ax.axhline(0,color='#333333',ls='--',lw=1,label='No attack')
        changes=[r for k,r in enumerate(rows) if k==0 or
                 (r['attacker_response'],r['outcome'])!=(rows[k-1]['attacker_response'],rows[k-1]['outcome'])]
        intervals=[]
        for k,r in enumerate(changes):
            if r['budget']>limit:break
            if k:ax.axvline(r['budget'],ls=':',color=GRAY)
            label={'blocked':'Blocked','deterred':'Deterrence'}.get(r['outcome'],r['attacker_response'])
            label=label.replace('Modicon M221','M221')
            end=changes[k+1]['budget']-1 if k+1<len(changes) else rows[-1]['budget']
            intervals.append(f"{label}: B={r['budget']}–{end}")
        ax.text(0,1.02,' | '.join(intervals),transform=ax.transAxes,fontsize=8)
        ax.set(xlabel='Defense budget',ylabel='Attacker net utility',xlim=(0,limit))
        ax.set_title(f"{ident}: {case['title_en']}",fontsize=11,pad=29)
        ax.legend(fontsize=8,loc='best')
    fig.text(.08,.015,'Utilities are evaluated after the optimal defense at each budget. Missing lines indicate unreachable targets, not zero utility.',fontsize=9)
    fig.tight_layout(rect=(0,.04,1,1),h_pad=3);save(fig,'attacker_tradeoffs')
    fig,axes=plt.subplots(2,2,figsize=(12,8))
    for ax,case in zip(axes.flat,cases):
        rows=[r for r in budgets if r['scenario']==case['id']];limit=int(rows[0]['minimum_blocking_cost'])+5
        x=[r['budget'] for r in rows]
        ax.step(x,[r['objective'] for r in rows],where='post',color=BLUE,lw=2,label='Proposed / enumeration')
        ax.fill_between(x,[r['cvss_min'] for r in rows],[r['cvss_max'] for r in rows],step='post',color=ORANGE,alpha=.2)
        ax.step(x,[r['cvss_median'] for r in rows],where='post',color=ORANGE,label='CVSS median (band: ties)')
        ax.step(x,[r['cheapest_objective'] for r in rows],where='post',color=GRAY,ls='--',label='Cheapest first')
        ax.axhline(rows[0]['empty_objective'],color=RED,ls=':',label='No defense')
        ax.axvline(rows[0]['minimum_blocking_cost'],color='#55606b',ls=':',lw=.8)
        ax.set(xlabel='Defense budget',ylabel='Patch cost + chosen-target loss',xlim=(0,limit))
        ax.set_title(case['id']+': '+case['title_en'],fontsize=11);ax.legend(fontsize=7.5)
    fig.text(.08,.01,'Dotted vertical line: minimum cost to make both targets unreachable. The full budget sweeps are saved in results/budgets.csv.',fontsize=8)
    fig.tight_layout(rect=(0,.03,1,1));save(fig,'budget_effect')


def build_report():
    started=time.perf_counter();(HERE/'figures').mkdir(exist_ok=True)
    bundle=read('assumptions.json');cases=bundle['scenarios'];scores=bundle['cvss'];manifest=read('manifest.json')
    for path,h in manifest['input_sha256'].items():assert hashlib.sha256((HERE.parents[1]/path).read_bytes()).hexdigest()==h,path
    assert hashlib.sha256((HERE/'assumptions.json').read_bytes()).hexdigest()==manifest['assumptions_sha256']
    budgets=read('results/budgets.json');repeats=read('results/repeats.json');counters=read('results/counterfactuals.json')
    transitions=read('results/transitions.json');baseline=read('results/baselines.json');mapping=read('node_mapping.json');audit=read('audit.json')
    from run_case_study import dump,write_csv
    lookup={(r['scenario'],r['budget']):r for r in budgets}
    timing=[];comparison=[];cost_rows=[];focus=[]
    for case in cases:
        ident=case['id'];main=lookup[ident,case['main_budget']]
        for label in ('main','unbudgeted'):
            rows=[r for r in repeats if r['scenario']==ident and r['case']==label]
            for key in ('build_seconds','optimize_seconds','solve_game_seconds','process_wall_seconds'):
                timing.append(dict(scenario=ident,case=label,stage=key,**stats(rows,key)))
        for b in case['focus_budgets']:
            focus.append(lookup[ident,b])
        methods=[('Proposed',main)]
        enumeration=read(f'results/{ident}/enumeration.json')
        methods.append(('Enumeration',min((r for r in enumeration if r['defense_cost']<=case['main_budget']),key=lambda r:r['objective'])))
        baserows=[r for r in baseline if r['scenario']==ident and r['budget']==case['main_budget']]
        methods += [('No defense',next(r for r in baserows if r['method']=='empty')),
                    ('Cheapest first',next(r for r in baserows if r['method']=='cheapest')),
                    ('CVSS best tie order',min((r for r in baserows if r['method']=='cvss'),key=lambda r:r['objective'])),
                    ('CVSS worst tie order',max((r for r in baserows if r['method']=='cvss'),key=lambda r:r['objective']))]
        for method,row in methods:
            comparison.append(dict(scenario=ident,budget=case['main_budget'],method=method,
                patched_cves=row['patched_cves'],defense_cost=row['defense_cost'],remaining_loss=row['remaining_loss'],
                objective=row['objective'],gap_to_optimum=row['objective']-main['objective'],
                attacker_response=row['attacker_response'],outcome=row['outcome'],goals=row['goals']))
        for v in case['vulnerabilities']:
            cost_rows.append(dict(scenario=ident,evidence=case['evidence'],service=v['service'],cve=v['cve'],
                attack_cost=v['attack_cost'],defense_cost=v['defense_cost'],cvss=scores[v['cve']]['score']))
    for name,rows in [('comparison',comparison),('timing_summary',timing),('focus_cases',focus)]:
        dump(HERE/'results'/f'{name}.json',rows);write_csv(HERE/'results'/f'{name}.csv',rows)
    write_csv(HERE/'costs.csv',cost_rows)
    network_figures(cases,budgets,counters,mapping);curves(cases,budgets)
    # Compact overview of each cost set at its designated constrained budget.
    table=[]
    for case in cases:
        row=lookup[case['id'],case['main_budget']];gs={g['name']:g for g in row['goals']}
        table.append([case['id'],num(case['main_budget']),patch_label(row,mapping,True),num(row['defense_cost']),
            num(gs['Redis']['utility']) if gs['Redis']['reachable'] else 'Blocked',
            num(gs['Modicon M221']['utility']) if gs['Modicon M221']['reachable'] else 'Blocked',
            row['attacker_response'],num(row['objective'])])
    fig,ax=plt.subplots(figsize=(15,3.3));ax.axis('off')
    artist=ax.table(cellText=table,colLabels=['Case','Budget','Optimal patch','Spending','Redis utility','M221 utility','Attacker choice','Objective'],
        cellLoc='center',loc='center',colWidths=[.045,.07,.19,.09,.12,.12,.16,.09])
    artist.auto_set_font_size(False);artist.set_fontsize(9);artist.scale(1,2.2)
    for (i,j),cell in artist.get_celld().items():
        cell.set_edgecolor('white');cell.set_facecolor('#dfeaf5' if i==0 else ('#f0f4f8' if i%2 else '#fafafa'))
    ax.set_title('One reference cost set and three illustrative cost sets',pad=8)
    save(fig,'strategy_comparison')
    doc=['# 六主机 Case Study：多套成本下的攻防权衡','',
        '所有成本、预算、收益、损失和效用均显示为纯数值。S1 是基于修复操作与工时拆分的合理估算；S2–S4 是为展示机制刻意设计的参数，不主张现实代表性。',
        '', '四套场景使用同一张攻击图、同一组五项补丁和同一组目标价值，仅改变攻防成本。Redis 的收益/损失固定为 60/200；工业控制器固定为 120/1000。',
        '', '## 先看结果','', '![总览](figures/strategy_comparison.png)','',
        '| 场景 | 主要现象 | 主预算 | 最优修补 | 费用 | 攻击者响应 | J |','|---|---|---:|---|---:|---|---:|']
    for case in cases:
        r=lookup[case['id'],case['main_budget']]
        doc.append(f"| {case['id']} | {case['title']} | {case['main_budget']} | {patch_label(r,mapping)} | {r['defense_cost']:g} | {response(r)} | {r['objective']:g} |")
    doc += ['', '## 模型与成本设置','',
        f"通过 MulVAL 生成 {audit['nodes']} 个节点、{audit['edges']} 条边的真实推理图。五项补丁对应 Apache、VPN、Tomcat、Redis、RDP；控制器漏洞不作为补丁候选。原始六主机目录保持不变。",'',
        '![拓扑](figures/topology.png)','',
        '攻击者在每个可达目标上计算 **净收益 = 目标收益 − 最低攻击成本**，再与放弃攻击的 0 比较。不可达目标不参与选择，不能把它的净收益记作 0。防御者最小化 **J = 修补成本 + 攻击者所选目标损失**，不对所有目标损失求和。净收益相同时沿用有利于防御者的强 Stackelberg 约定。','',
        '| 服务 / CVE | S1 攻击 / 修补 | S2 攻击 / 修补 | S3 攻击 / 修补 | S4 攻击 / 修补 |','|---|---|---|---|---|']
    for i,v in enumerate(cases[0]['vulnerabilities']):
        doc.append('| '+v['service']+' / '+v['cve']+' | '+' | '.join(f"{c['vulnerabilities'][i]['attack_cost']:g} / {num(c['vulnerabilities'][i]['defense_cost'])}" for c in cases)+' |')
    doc += ['', '“—”表示不可选择该补丁。成本冻结于 [assumptions.json](assumptions.json)，逐项配置见 [costs.csv](costs.csv)。只有六个漏洞利用动作计攻击成本，网络可达性等辅助规则不收费。','',
        '## 各场景的预算与目标选择','']
    for case in cases:
        ident=case['id'];min_block=lookup[ident,0]['minimum_blocking_cost']
        doc += [f"### {ident}：{case['title']}",'',case['intent'],'',
            f"同时阻断两个目标所需的最低修补费用为 **{min_block:g}**。以下预算点均由所提方法实际求解，并与全部 32 个组合枚举核对。",'',
            '| 预算 | 最优修补 | 费用 | Redis：收益−成本 | 控制器：收益−成本 | 攻击响应 | 剩余损失 | J |',
            '|---:|---|---:|---|---|---|---:|---:|']
        for b in case['focus_budgets']:
            row=lookup[ident,b];gs={g['name']:g for g in row['goals']}
            doc.append(f"| {b} | {patch_label(row,mapping)} | {row['defense_cost']:g} | {utility_cell(gs['Redis'])} | {utility_cell(gs['Modicon M221'])} | {response(row)} | {row['remaining_loss']:g} | {row['objective']:g} |")
        doc += ['',f"![{ident} 攻防图](figures/{ident}_defense.png)",'']
        if ident=='S3':
            alternative=next(r for r in counters if r['scenario']==ident and r['policy']=='patch_redis_only')
            original=lookup[ident,case['main_budget']]
            doc += [f"预算为 {case['main_budget']} 时，单独修补 Redis 是可行方案，费用为 {alternative['defense_cost']:g}，但会把攻击者转向工业控制器，使 J 从 {original['objective']:g} 增至 {alternative['objective']:g}。因此当前模型的最优决策是不花预算。这是模型内对自适应攻击者的响应，不是对现实中保留漏洞的运维建议。",'']
        if ident=='S4':
            row=lookup[ident,case['main_budget']]
            doc += [f"预算 {case['main_budget']} 低于完全阻断费用 {min_block:g}，但修补低成本入口后，剩余 VPN 路径仍让两个目标在逻辑上可达。两个目标的净收益均为负，攻方选择收益为 0 的空攻击；这与“路径被切断”是不同现象。",'']
    doc += ['## 全预算结果与比较','', '![攻击者权衡](figures/attacker_tradeoffs.png)','',
        '曲线展示每个预算下最优防御实施后的目标净收益；断开的曲线表示目标不可达。图中放大策略变化所在的预算区间，完整预算扫描保存于 CSV。','',
        '![预算效果](figures/budget_effect.png)','',
        '| 场景 | 最优策略适用的预算区间 | 修补 | 攻击响应 | J |','|---|---|---|---|---:|']
    for r in transitions:doc.append(f"| {r['scenario']} | {r['budget']}–{r['budget_end']} | {patch_label(r,mapping)} | {response(r)} | {r['objective']:g} |")
    doc += ['', '| 场景 | 方法（主预算） | 修补 | 费用 | 攻击响应 | J | 与最优值差距 |',
            '|---|---|---|---:|---|---:|---:|']
    for r in comparison:doc.append(f"| {r['scenario']} | {r['method']} | {patch_label(r,mapping)} | {r['defense_cost']:g} | {response(r)} | {r['objective']:g} | {r['gap_to_optimum']:g} |")
    doc += ['', 'CVSS 排序使用保存的 NVD 3.1 基础分数，穷举全部同分排序并报告最好/最差结果；低费用策略按费用排序，同费按 CVE 排序。两种排序策略均跳过当前不可负担项、继续检查后续候选，不根据攻击响应回调排序。','',
        '## 哪些结论来自合理成本，哪些仅展示机制','',
        'S1 的数值来自原工时与停机估算按共同参考比例缩放，详细步骤与依据见 [COSTS_AND_SOURCES.md](COSTS_AND_SOURCES.md)。S2–S4 有意改变成本，只证明所给参数下能够发生目标转移、低收益目标被偏好、防御反效果、以及不切断路径的威慑；不把它们表述为经验分布或现实预测。','',
        'CVSS 可描述漏洞严重性、帮助核对利用前提，并作为比较基线；它不是修补成本、成功概率或目标净收益。三套设计参数不声称由 CVSS 推导。[FIRST 使用说明](https://www.first.org/cvss/v3.1/user-guide)。','',
        '拓扑限制：两个目标共用入口和 Tomcat。在两个目标都可达且仅共同前缀的成本改变时，两个净收益会减去同一个量，目标间的排序不变；可能发生的是一起变得不值得攻击。S2 的目标转移通过阻断控制器分支实现，S3 的偏好差异通过分支攻击成本实现，S4 展示共同前缀变贵后的放弃。','',
        '## 最优性与时间','',
        f"四套场景各枚举 32 个组合。共享图的 32 种补丁组合均重新运行 MulVAL 核验可达性；成本改变不会改变这些可达性事实。共 {audit['budget_points']} 个预算点和 {audit['repeated_solves']} 次重复运行，所有解都通过独立核验。SCIP 与枚举比较的最优性只针对给定图、五项补丁、确定性成本和强 Stackelberg 约定。",'',
        '| 场景 | 设置 | 建模中位数 s | 优化中位数 s | 端到端中位数 s | 端到端 Q1–Q3 s |',
        '|---|---|---:|---:|---:|---|']
    for case in cases:
        for label in ('main','unbudgeted'):
            t={r['stage']:r for r in timing if r['scenario']==case['id'] and r['case']==label}
            wall=t['process_wall_seconds']
            doc.append(f"| {case['id']} | {'主预算 '+str(case['main_budget']) if label=='main' else '无预算上限'} | {t['build_seconds']['median']:.6f} | {t['optimize_seconds']['median']:.6f} | {wall['median']:.6f} | {wall['q1']:.6f}–{wall['q3']:.6f} |")
    doc += ['', '各设置顺序运行十个独立 Python 进程，SCIP 单线程、种子 7–16、零间隙限制。端到端时间包括导入、读取、求解和结果写出；主机并非独占。小案例用于解释决策，不据此主张规模或速度优势。','',
        '## 论文段落与复现','']
    s2=lookup['S2',5];s3=lookup['S3',5];s4=lookup['S4',4]
    paper=(f"为分析不同成本结构下的攻防决策，本文在同一六主机攻击图上设置一套基于维护工作量的成本估算和三套机制展示参数，固定两个目标的收益与损失，仅改变攻防成本。"
           f"在 S2 中，完全阻断攻击至少需要 {s2['minimum_blocking_cost']:g}，当预算仅为 5 时，所提方法选择修补 CVE-2019-0708，花费 {s2['defense_cost']:g}，使攻击者从工业控制器转向 Redis，防御目标值降为 {s2['objective']:g}。"
           f"在 S3 中，两个目标均可达，但 Redis 的净收益为 {s3['goals'][0]['utility']:g}，高于工业控制器的 {s3['goals'][1]['utility']:g}，说明攻方比较的是收益扣除成本后的效用。"
           f"在 S4 中，仅花费 {s4['defense_cost']:g} 即可使剩余攻击路径的净收益均为负，虽然目标仍可达，攻击者仍选择放弃。所有结果均与完整枚举一致。机制展示参数不代表现实成本分布，相关最优性限定于所设模型与参数。")
    doc += [paper,'',
        '```bash\npython3 SP/08_case_study/run_case_study.py\npython3 SP/08_case_study/run_case_study.py --verify-only\npython3 SP/08_case_study/run_case_study.py --report-only\n```','',
        '完整运行直接覆盖本案例旧结果和图片，不保留旧批次；来源快照、输入及代码保留。修改 case_data.py 中 SCENARIOS 可调整各套成本与展示预算。','',
        '输出入口：[每个目标的成本与效用](results/attacker_choices.csv)、[关键预算点](results/focus_cases.csv)、[全部比较](results/comparison.csv)、[单补丁反事实](results/counterfactuals.csv)、[LaTeX 表格](results/comparison.tex)、[最优性审计](audit.json)、[输入及代码哈希](manifest.json)、[完整攻击图](figures/attack_graph.pdf)。所有图同时提供 PDF/SVG/PNG。']
    (HERE/'CASE_STUDY.md').write_text('\n'.join(doc)+'\n')
    (HERE/'paper_paragraph.md').write_text(paper+'\n')
    tex=['\\begin{tabular}{llrrrr}','\\hline','Case & Method & Patch cost & Loss & $J$ & $J-J^*$ \\\\', '\\hline']
    for r in comparison:tex.append(f"{r['scenario']} & {r['method']} & {r['defense_cost']:g} & {r['remaining_loss']:g} & {r['objective']:g} & {r['gap_to_optimum']:g} \\\\")
    tex+=['\\hline','\\end{tabular}']
    (HERE/'results/comparison.tex').write_text('\n'.join(tex)+'\n')
    cost_doc=['# 成本依据与设计参数','',
        'S1 保留原工时与维护操作依据，并按统一参考比例数值化：攻击成本=攻击工时×2；修补成本=修补工时×2+停机小时×中断系数。中断系数按服务取 10 或 20。图表只显示数值，不赋予命名单位，也不作实际报价。',
        '', '例如 Tomcat：3×2+0.25×20=11。原始人工和中断估算以及缩放参考值保存在 S1 配置中，厂商资料支持操作步骤，具体工时仍为场景假设。',
        '', 'S2–S4 的攻防成本是明确标注的设计值，不要求现实合理性，不给这些数值附会工时或厂商依据。目标收益/损失在四组中固定为 Redis 60/200、控制器 120/1000。','']
    for v in cases[0]['vulnerabilities']:
        c=scores[v['cve']]
        cost_doc += [f"## {v['service']} — {v['cve']}",'',
            f"版本：{v['version']}。本 CVE 历史修复：{v['fix'] or '未核实可用补丁，不作为候选'}。",'',
            '前提：'+v['precondition'],'','处置：'+v['remediation'],'',
            f"S1 攻击工时（准备/适配/执行验证）：{v['attack_hours']}；维护工时（评估/备份/安装/验证）：{v['patch_hours']}；停机小时：{v['downtime']}。{v['rationale']}",'',
            f"CVSS {c['version']} 基础分数 {c['score']:g}，向量 `{c['vector']}`。",'',
            f"[厂商或协调机构依据]({v['source']})；[NVD]({c['url']})；[来源快照]({c['snapshot']})，读取于 {c['retrieved_at']}。",'']
    cost_doc += ['历史修复版本不代表当前生产升级建议。工业控制器仅推导配置修改；TCP/502 是依据公告建立的受控管理通路抽象，不声称完整复现底层攻击报文。', '',
        'Fortinet CNA 记录存在包含时间指标的向量及 9.3 字段，本案例统一取 NVD 3.1 基础向量及 9.8；两份原始快照均保留。', '',
        '[CVSS 语义：FIRST](https://www.first.org/cvss/v3.1/user-guide)。']
    (HERE/'COSTS_AND_SOURCES.md').write_text('\n'.join(cost_doc)+'\n')
    dump(HERE/'report_timing.json',{'figure_and_report_seconds':time.perf_counter()-started,
         'report_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
