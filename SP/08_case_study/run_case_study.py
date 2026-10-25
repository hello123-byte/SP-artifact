#!/usr/bin/env python3
"""Rebuild, solve, independently verify, and report the six-host case study."""
from __future__ import annotations
import argparse, copy, csv, hashlib, itertools, json, math, os, platform, re, shutil
import subprocess, sys, time, statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from case_data import assumptions, scenario_data, GOALS

ENV = {**os.environ, 'OMP_NUM_THREADS':'1', 'OPENBLAS_NUM_THREADS':'1',
       'MKL_NUM_THREADS':'1', 'NUMEXPR_NUM_THREADS':'1', 'PYTHONHASHSEED':'0',
       'PYTHONDONTWRITEBYTECODE':'1'}
ENV.update(MULVALROOT=str(ROOT/'tools/mulval'), XSBHOME=str(ROOT/'tools/XSB'))
ENV['PATH'] = f"{ROOT/'tools/XSB/bin'}:{ROOT/'tools/mulval/bin'}:{ROOT/'tools/mulval/utils'}:"+ENV['PATH']
for key in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS'):
    os.environ[key]='1'


def dump(path, data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2,ensure_ascii=False,allow_nan=False)+'\n')


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_csv(path, rows):
    rows=list(rows)
    if not rows: return
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for r in rows:
            w.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in r.items()})


def read_graph(folder):
    folder=Path(folder)
    vertices={}
    for r in csv.reader((folder/'VERTICES.CSV').read_text().splitlines()):
        if r:
            assert int(r[0]) not in vertices
            vertices[int(r[0])]=dict(id=int(r[0]),label=r[1],type=r[2],score=float(r[3]))
    arcs=[(int(r[0]),int(r[1])) for r in csv.reader((folder/'ARCS.CSV').read_text().splitlines()) if r]
    assert len(set(arcs))==len(arcs)
    assert all(a in vertices and b in vertices for a,b in arcs)
    children={i:[] for i in vertices}
    for a,b in arcs:children[a].append(b)
    visited=set();active=set();order=[]
    def dfs(i):
        assert i not in active, f'Cycle at node {i}'
        if i in visited:return
        active.add(i)
        for j in children[i]:dfs(j)
        active.remove(i);visited.add(i);order.append(i)
    for i in vertices:dfs(i)
    return vertices,arcs,children,order


def run_mulval(input_text, target):
    target=Path(target);target.mkdir(parents=True,exist_ok=True)
    # Always fresh: no stale graph can masquerade as a successful inference.
    scratch=HERE/'.work'/target.name
    if scratch.exists():shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    (target/'input.P').write_text(input_text)
    command=[str(ROOT/'tools/mulval/utils/graph_gen.sh'), str(target/'input.P'),
             '-a',str(HERE/'input/additional_rules.P'),'-l']
    start=time.perf_counter()
    proc=subprocess.run(command,cwd=scratch,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
    elapsed=time.perf_counter()-start
    (target/'invocation.log').write_bytes(proc.stdout)
    for name in ('xsb_log.txt','AttackGraph.txt','VERTICES.CSV','ARCS.CSV','trace_output.P','running_rules.P'):
        if (scratch/name).exists():shutil.copy2(scratch/name,target/name)
    log=(target/'xsb_log.txt').read_text() if (target/'xsb_log.txt').exists() else ''
    errors = re.search(r'\+\+Error|\+\+ABORT|syntax error',log,re.I)
    empty = (proc.returncode == 1 and 'No attack paths found.' in (target/'invocation.log').read_text()
             and 'End XSB' in log and (target/'trace_output.P').exists() and not errors)
    if empty:
        # MulVAL exits 1 before CSV output for a successfully inferred empty graph.
        for name in ('VERTICES.CSV','ARCS.CSV'):(target/name).write_text('')
    elif proc.returncode or errors:
        raise RuntimeError(f'MulVAL failed: {target}')
    assert (target/'VERTICES.CSV').exists() and (target/'ARCS.CSV').exists(), target
    v,a,_,_=read_graph(target)
    dump(target/'meta.json',dict(seconds=elapsed,returncode=proc.returncode,command=command,
          input_sha256=sha(target/'input.P'),vertices=len(v),edges=len(a),
          no_attack_paths=empty,empty_csv_normalized=empty))
    return {node['label'] for node in v.values() if node['type']=='OR'},elapsed


def prepare_config(data, graph):
    vertices,arcs,children,_=graph
    label_ids={v['label']:i for i,v in vertices.items()}
    assert all(label in label_ids for label in GOALS)
    config={'defaults':{'solver':'scip','mip_gap':0.,'target_closure':True,
              'attack_cost_source':'constant','action_attack_cost':0.,'leaf_attack_cost':0.,
              'defendable_mode':'vul','budget':None},'nodes':{},'goals':{}}
    mapping={}
    for i,v in vertices.items():
        config['nodes'][str(i)]={'attack_cost':0.,'defendable':False,'label':v['label']}
    for vuln in data['vulnerabilities']:
        prefix=f"vulExists({vuln['host']},'{vuln['cve']}',{vuln['software']}"
        leaves=[i for i,v in vertices.items() if v['type']=='LEAF' and v['label'].startswith(prefix+',')]
        assert len(leaves)==1,(prefix,leaves)
        leaf=leaves[0]
        # Match actual exploit rules through the CVE prerequisite; no rule/node IDs hard-coded.
        actions=[i for i in vertices if vertices[i]['type']=='AND' and leaf in children[i]
                 and ('remote exploit of a server program' in vertices[i]['label'] or
                      'remote unauthorized IPv4 configuration change' in vertices[i]['label'])]
        assert len(actions)==1,(prefix,actions)
        for i in actions:config['nodes'][str(i)]['attack_cost']=vuln['attack_cost']
        if vuln['defense_cost'] is not None:
            config['nodes'][str(leaf)].update(defendable=True,defense_cost=vuln['defense_cost'])
        mapping[vuln['cve']]=dict(host=vuln['host'],leaf=leaf,actions=actions,
              service=vuln['service'],defendable=vuln['defense_cost'] is not None)
    for label,g in data['goals'].items():config['goals'][str(label_ids[label])]={**g,'label':label,'enabled':True}
    assert sum(n['defendable'] for n in config['nodes'].values())==5
    assert sum(n['attack_cost']>0 for n in config['nodes'].values())==6
    return config,mapping


def evaluate(graph, config, patches):
    """Independent DAG evaluation: no core solver/baseline evaluation functions."""
    vertices,arcs,children,order=graph
    patches=set(patches)
    candidates={int(i) for i,n in config['nodes'].items() if n['defendable']}
    assert patches<=candidates
    costs={};witness={}
    for i in order:
        kind=vertices[i]['type'];deps=children[i]
        if kind=='LEAF':costs[i]=math.inf if i in patches else 0.;witness[i]=[]
        elif kind=='AND':
            assert deps
            costs[i]=config['nodes'][str(i)]['attack_cost']+sum(costs[j] for j in deps)
            witness[i]=deps
        elif kind=='OR':
            assert deps
            best=min(deps,key=lambda j:(costs[j],j));costs[i]=costs[best];witness[i]=[best]
        else:raise ValueError(kind)
    details=[]
    for key,g in config['goals'].items():
        i=int(key);reachable=math.isfinite(costs[i])
        details.append(dict(id=i,label=g['label'],name=g['name'],reachable=reachable,
            min_attack_cost=costs[i] if reachable else None,
            utility=g['reward']-costs[i] if reachable else None,reward=g['reward'],loss=g['loss']))
    possible=[g for g in details if g['reachable']]
    best=max([0.]+[g['utility'] for g in possible])
    chosen=None
    if best>1e-9:
        chosen=min((g for g in possible if abs(g['utility']-best)<1e-9),key=lambda g:(g['loss'],g['id']))
    selected_actions=[]
    def trace(i):
        if vertices[i]['type']=='AND' and config['nodes'][str(i)]['attack_cost']>0:selected_actions.append(i)
        for j in witness[i]:trace(j)
    if chosen:trace(chosen['id'])
    spending=sum(config['nodes'][str(i)]['defense_cost'] for i in patches)
    loss=chosen['loss'] if chosen else 0.
    reachable_hosts=sorted({match.group(1) for i,node in vertices.items()
        if math.isfinite(costs[i]) and (match:=re.match(r'(?:execCode|modifyNetworkConfig)\((h[1-6])[,)]',node['label']))})
    outcome='attack' if chosen else ('deterred' if possible else 'blocked')
    return dict(selected_defenses=sorted(patches),defense_cost=spending,remaining_loss=loss,
        outcome=outcome,reachable_hosts=reachable_hosts,
        objective=spending+loss,attacker_response=chosen['name'] if chosen else 'No attack',
        attacker_utility=best,attack_cost=chosen['min_attack_cost'] if chosen else None,
        attack_actions=selected_actions,goals=details)


def enumerate_all(graph, config):
    ids=sorted(int(i) for i,n in config['nodes'].items() if n['defendable'])
    return [dict(mask=mask,**evaluate(graph,config,[i for j,i in enumerate(ids) if mask&(1<<j)]))
            for mask in range(1<<len(ids))]


def optimum(rows,budget):
    feasible=[r for r in rows if budget is None or r['defense_cost']<=budget+1e-9]
    val=min(r['objective'] for r in feasible)
    return val,[r for r in feasible if abs(r['objective']-val)<1e-7]


def attach_names(row,mapping):
    return {**row,'patched_cves':[c for c,m in mapping.items() if m['leaf'] in row['selected_defenses']]}


def worker(task_file):
    # An isolated process per solve keeps imports/startup visible in end-to-end timings.
    start=time.perf_counter();task=json.loads(Path(task_file).read_text())
    import solve_mulval__stackelberg_main as core
    import pyscipopt
    config=task['config'];graph=read_graph(HERE/'graph')
    models=[];original=core.create_model_backend
    def backend(solver,time_limit,mip_gap):
        model,qs=original(solver,time_limit,mip_gap)
        model.setIntParam('parallel/maxnthreads',1)
        model.setIntParam('randomization/randomseedshift',task['seed'])
        models.append(model);return model,qs
    core.create_model_backend=backend
    result=core.solve_game(vertices=graph[0],arcs=graph[1],game_config=config,goal_ids=None,
        default_reward=0.,default_loss=0.,goal_rewards_raw=None,goal_losses_raw=None,
        default_defense_cost=0.,defense_costs_raw=None,defendable_mode=None,budget=task['budget'],
        attack_cost_source='constant',default_action_cost=0.,default_leaf_cost=0.,node_attack_costs_raw=None,
        cost_big_m_override=None,target_closure=True,time_limit=60.,mip_gap=0.,
        warm_start_key_path=False,solver='scip',write_lp=None)
    model=models[0]
    result['certificate']={'primal_bound':model.getPrimalbound(),'dual_bound':model.getDualbound(),
        'search_nodes':model.getNNodes(),'threads':1,'pyscipopt':pyscipopt.__version__}
    result['worker_wall_seconds']=time.perf_counter()-start
    dump(Path(task_file).with_name('result.json'),result)


def solve(config,budget,folder,seed=7):
    folder=HERE/'results'/folder;folder.mkdir(parents=True,exist_ok=True)
    task={'config':config,'budget':budget,'seed':seed}
    dump(folder/'task.json',task)
    start=time.perf_counter()
    try:
        p=subprocess.run([sys.executable,str(Path(__file__)), '--worker',str(folder/'task.json')],
            env=ENV,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=70)
    except subprocess.TimeoutExpired as exc:
        (folder/'solver.log').write_bytes(exc.stdout or b'')
        dump(folder/'failure.json',{'status':'hard_timeout','seconds':time.perf_counter()-start})
        raise RuntimeError(f'Solve hard timeout: {folder}') from exc
    elapsed=time.perf_counter()-start
    (folder/'solver.log').write_bytes(p.stdout)
    if p.returncode:raise RuntimeError(f'Solve failed: {folder}/solver.log')
    result=json.loads((folder/'result.json').read_text())
    result['process_wall_seconds']=elapsed
    dump(folder/'result.json',result)
    return result


def checked_solve(graph,config,mapping,budget,folder,seed=7,rows=None):
    result=solve(config,budget,folder,seed)
    if result['objective_cost_form'] is None:raise RuntimeError(f'No incumbent: {folder}')
    ids=[x['id'] for x in result['selected_defenses']]
    evaluation=evaluate(graph,config,ids)
    assert budget is None or evaluation['defense_cost']<=budget+1e-7
    assert abs(evaluation['objective']-result['objective_cost_form'])<1e-6
    exact,opts=optimum(rows if rows is not None else enumerate_all(graph,config),budget)
    error=evaluation['objective']-exact
    assert abs(error)<1e-6, (folder,error)
    assert abs(evaluation['attacker_utility']-result['attacker_utility'])<1e-6
    if result['status']=='optimal':assert result['relative_gap']<=1e-7
    result.update(independent_validation=True,enumerated_optimum=exact,objective_error=error)
    dump(HERE/'results'/folder/'result.json',result)
    return attach_names({**evaluation,'status':result['status'],'solver_gap':result['relative_gap'],
       'optimality_error':error,'enumerated_optimal_sets':[r['selected_defenses'] for r in opts],
       'build_seconds':result['timings_seconds']['build_mip'],
       'optimize_seconds':result['timings_seconds']['optimize'],
       'solve_game_seconds':result['timings_seconds']['total_solve_game'],
       'process_wall_seconds':result['process_wall_seconds'],**result['certificate']},mapping)


def cvss_data(data):
    result={}
    for v in data['vulnerabilities']:
        path=HERE/'sources'/f"{v['cve']}_nvd.json"
        record=json.loads(path.read_text())
        metrics=record['record']['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31']
        selected=next(x for x in metrics if x['source']=='nvd@nist.gov')
        cv=selected['cvssData']
        result[v['cve']]=dict(score=cv['baseScore'],vector=cv['vectorString'],version=cv['version'],
            source='NVD',url='https://nvd.nist.gov/vuln/detail/'+v['cve'],
            snapshot=str(path.relative_to(HERE)),retrieved_at=record['retrieved_at'])
    return result


def baselines(graph,config,mapping,scores,budget):
    ids=[m['leaf'] for m in mapping.values() if m['defendable']]
    byid={m['leaf']:c for c,m in mapping.items()}
    def greedy(order):
        selected=[];used=0.
        for i in order:
            c=config['nodes'][str(i)]['defense_cost']
            if budget is None or used+c<=budget+1e-9:selected.append(i);used+=c
        return attach_names(evaluate(graph,config,selected),mapping)
    groups=defaultdict(list)
    for i in ids:groups[scores[byid[i]]['score']].append(i)
    tie_orders=[sum((list(p) for p in group),[]) for group in itertools.product(
        *(list(itertools.permutations(groups[score])) for score in sorted(groups,reverse=True)))]
    start=time.perf_counter();cvss=[]
    for order in tie_orders:
        t=time.perf_counter();row=greedy(order)
        cvss.append(dict(method='cvss',order=[byid[i] for i in order],seconds=time.perf_counter()-t,**row))
    elapsed=time.perf_counter()-start
    start=time.perf_counter()
    cheap=greedy(sorted(ids,key=lambda i:(config['nodes'][str(i)]['defense_cost'],byid[i])))
    cheap.update(method='cheapest',seconds=time.perf_counter()-start)
    start=time.perf_counter();empty=attach_names(evaluate(graph,config,[]),mapping)
    empty.update(method='empty',seconds=time.perf_counter()-start)
    return dict(cvss=cvss,cvss_all_orders_seconds=elapsed,cheapest=cheap,empty=empty)


def validate_mulval(graph,config,mapping,rows,input_text):
    checks=[];elapsed=0.
    id_cve={m['leaf']:c for c,m in mapping.items()}
    for row in rows:
        removed=[id_cve[i] for i in row['selected_defenses']]
        edited='\n'.join(line for line in input_text.splitlines()
               if not (line.startswith('vulExists(') and any("'"+c+"'" in line for c in removed)))+'\n'
        target=HERE/'validation'/f"mask_{row['mask']:02d}"
        reachable,seconds=run_mulval(edited,target);elapsed+=seconds
        expected={g['label'] for g in row['goals'] if g['reachable']}
        actual=set(GOALS)&reachable
        assert expected==actual,(removed,expected,actual)
        checks.append(dict(mask=row['mask'],removed_cves=removed,expected_goals=sorted(expected),
                           mulval_goals=sorted(actual),passed=True,seconds=seconds))
    # Structural properties derived from service identities, not original graph IDs.
    ids={m['host']:m['leaf'] for m in mapping.values()}
    reach=lambda hosts:{g['name'] for g in evaluate(graph,config,[ids[h] for h in hosts])['goals'] if g['reachable']}
    assert reach(['h3'])==set()
    assert reach(['h1'])==reach(['h2'])=={'Redis','Modicon M221'}
    assert reach(['h4'])=={'Modicon M221'} and reach(['h5'])=={'Redis'}
    assert evaluate(graph,config,[ids['h5']])['attacker_response']=='Redis'
    dump(HERE/'validation/checks.json',dict(passed=True,combinations=checks,seconds=elapsed))
    return elapsed



def freeze_manifest(bundle):
    source_paths=[HERE/'case_data.py',HERE/'run_case_study.py',HERE/'test_case_study.py',
        HERE/'input/input.P',HERE/'input/additional_rules.P',HERE/'fetch_sources.py',
        ROOT/'solve_mulval__stackelberg_main.py',ROOT/'tools/mulval/kb/interaction_rules.P',
        ROOT/'tools/mulval/utils/graph_gen.sh']
    import pyscipopt,matplotlib
    dump(HERE/'assumptions.json',bundle)
    manifest=dict(started_at=datetime.now(timezone.utc).isoformat(),
        assumptions_sha256=sha(HERE/'assumptions.json'),
        input_sha256={str(p.relative_to(ROOT)):sha(p) for p in source_paths},
        source_snapshots={p.name:sha(p) for p in (HERE/'sources').glob('*.json')},
        environment={'python':sys.version,'platform':platform.platform(),
            'cpu':next((line.split(':',1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')),platform.processor()),
            'cpu_count':os.cpu_count(),'affinity':sorted(os.sched_getaffinity(0)),
            'pyscipopt':pyscipopt.__version__,'matplotlib':matplotlib.__version__,
            'threads':1,'timing_note':'Sequential fresh processes; host not reserved exclusively.'})
    dump(HERE/'manifest.json',manifest)
    return manifest


def verify_scenario_behavior(all_budgets, counterfactuals):
    lookup={(r['scenario'],r['budget']):r for r in all_budgets}
    a=lookup['S1',15];assert a['patched_cves']==['CVE-2017-12617'] and a['outcome']=='blocked'
    b=lookup['S2',5];assert b['patched_cves']==['CVE-2019-0708'] and b['attacker_response']=='Redis'
    assert lookup['S2',0]['attacker_response']=='Modicon M221'
    assert lookup['S2',17]['outcome']=='blocked'
    c=lookup['S3',5];assert c['patched_cves']==[] and c['attacker_response']=='Redis'
    goals={g['name']:g for g in c['goals']}
    assert all(g['reachable'] for g in goals.values())
    assert goals['Redis']['utility']==44 and goals['Modicon M221']['utility']==28
    adverse=next(r for r in counterfactuals if r['scenario']=='S3' and r['policy']=='patch_redis_only')
    assert adverse['attacker_response']=='Modicon M221' and adverse['objective']>c['objective']
    d=lookup['S4',4];assert d['patched_cves']==['CVE-2021-42013'] and d['outcome']=='deterred'
    assert all(g['reachable'] and g['utility']<0 for g in d['goals'])


def run_experiments():
    started=time.perf_counter()
    # The user explicitly requested replacing the previous results and figures.
    for name in ('results','figures','configs','validation','graph','.work'):
        target=HERE/name
        if target.exists():shutil.rmtree(target)
    for name in ('CASE_STUDY.md','COSTS_AND_SOURCES.md','paper_paragraph.md','audit.json',
                 'RUN_FAILED.md','game_config.json','node_mapping.json','costs.csv','report_timing.json'):
        (HERE/name).unlink(missing_ok=True)
    cases=scenario_data();scores=cvss_data(cases[0])
    bundle={'cost_display':'numbers_only','scenarios':cases,'cvss':scores,
            'design_note':'Only attack and defense costs vary; graph, rewards, losses and eligible patches are fixed.'}
    manifest=freeze_manifest(bundle)
    input_text=(HERE/'input/input.P').read_text()
    _,build_seconds=run_mulval(input_text,HERE/'graph')
    graph=read_graph(HERE/'graph');reference,mapping=prepare_config(cases[0],graph)
    dump(HERE/'node_mapping.json',mapping)
    print('Checking the shared graph against 32 fresh MulVAL runs.',flush=True)
    validation_seconds=validate_mulval(graph,reference,mapping,enumerate_all(graph,reference),input_text)
    all_budgets=[];all_repeats=[];all_baselines=[];all_counterfactuals=[];summaries=[]
    for case in cases:
        ident=case['id'];config,current_mapping=prepare_config(case,graph)
        assert current_mapping==mapping
        dump(HERE/'configs'/f'{ident}.json',config)
        t=time.perf_counter();rows=[attach_names(r,mapping) for r in enumerate_all(graph,config)]
        enum_seconds=time.perf_counter()-t
        dump(HERE/'results'/ident/'enumeration.json',rows)
        write_csv(HERE/'results'/ident/'enumeration.csv',rows)
        full_cuts=[r for r in rows if all(not g['reachable'] for g in r['goals'])]
        min_block_cost=min(r['defense_cost'] for r in full_cuts)
        minimal_cuts=[r for r in full_cuts if not any(set(other['selected_defenses'])<set(r['selected_defenses']) for other in full_cuts)]
        dump(HERE/'results'/ident/'minimal_cuts.json',minimal_cuts)
        for budget in range(case['budget_max']+1):
            row=checked_solve(graph,config,mapping,budget,f'{ident}/budgets/{budget:03d}',rows=rows)
            row=dict(scenario=ident,budget=budget,**row,
                     minimum_blocking_cost=min_block_cost,can_fully_block=budget>=min_block_cost)
            baseline=baselines(graph,config,mapping,scores,budget)
            row.update(cvss_min=min(r['objective'] for r in baseline['cvss']),
                       cvss_max=max(r['objective'] for r in baseline['cvss']),
                       cvss_median=statistics.median(r['objective'] for r in baseline['cvss']),
                       cheapest_objective=baseline['cheapest']['objective'],
                       empty_objective=baseline['empty']['objective'])
            all_budgets.append(row)
            for r in [*baseline['cvss'],baseline['cheapest'],baseline['empty']]:
                all_baselines.append(dict(scenario=ident,budget=budget,**r))
            if budget%30==0:print(ident,'budget',budget,'verified.',flush=True)
        for label,budget in [('main',case['main_budget']),('unbudgeted',None)]:
            for repeat in range(1,11):
                row=checked_solve(graph,config,mapping,budget,
                    f'{ident}/repeats/{label}/{repeat:02d}',seed=6+repeat,rows=rows)
                all_repeats.append(dict(scenario=ident,case=label,budget=budget,repeat=repeat,**row))
        # All single-patch decisions are evaluated explicitly, including adverse redirection.
        policies={'empty':[],**{f"patch_{m['host']}_only":[m['leaf']] for m in mapping.values() if m['defendable']}}
        policies['patch_redis_only']=policies.pop('patch_h4_only')
        for policy,ids in policies.items():
            row=attach_names(evaluate(graph,config,ids),mapping)
            all_counterfactuals.append(dict(scenario=ident,policy=policy,
                budget=case['main_budget'],feasible_at_main=row['defense_cost']<=case['main_budget'],**row))
        scenario_rows=[r for r in all_budgets if r['scenario']==ident]
        transitions=[r for i,r in enumerate(scenario_rows) if i==0 or
            (r['patched_cves'],r['attacker_response'],r['outcome']) !=
            (scenario_rows[i-1]['patched_cves'],scenario_rows[i-1]['attacker_response'],scenario_rows[i-1]['outcome'])]
        for i,r in enumerate(transitions):
            r=copy.deepcopy(r)
            r['budget_end']=transitions[i+1]['budget']-1 if i+1<len(transitions) else case['budget_max']
            summaries.append(r)
        dump(HERE/'results'/ident/'meta.json',{'enumeration_seconds':enum_seconds,'minimum_blocking_cost':min_block_cost})
        print(ident,'finished.',flush=True)
    verify_scenario_behavior(all_budgets,all_counterfactuals)
    for name,rows in [('budgets',all_budgets),('repeats',all_repeats),('baselines',all_baselines),
                      ('counterfactuals',all_counterfactuals),('transitions',summaries)]:
        dump(HERE/'results'/f'{name}.json',rows);write_csv(HERE/'results'/f'{name}.csv',rows)
    # One row per target and budget makes the attacker's comparison directly inspectable.
    goal_rows=[]
    for row in all_budgets:
        for g in row['goals']:
            goal_rows.append(dict(scenario=row['scenario'],budget=row['budget'],
                patched_cves=row['patched_cves'],chosen_target=row['attacker_response'],outcome=row['outcome'],
                **g))
    write_csv(HERE/'results/attacker_choices.csv',goal_rows)
    assert sha(HERE/'assumptions.json')==manifest['assumptions_sha256']
    manifest['generated_input_sha256']={str(p.relative_to(HERE)):sha(p) for p in
        [HERE/'graph/VERTICES.CSV',HERE/'graph/ARCS.CSV',HERE/'node_mapping.json',*sorted((HERE/'configs').glob('*.json'))]}
    dump(HERE/'manifest.json',manifest)
    dump(HERE/'audit.json',dict(passed=True,scenarios=len(cases),nodes=len(graph[0]),edges=len(graph[1]),
        node_types=dict(Counter(v['type'] for v in graph[0].values())),defense_candidates=5,
        combinations_per_scenario=32,mulval_checks=32,repeated_solves=len(all_repeats),
        budget_points=len(all_budgets),total_solves=len(all_repeats)+len(all_budgets),
        all_solutions_match_enumeration=True,all_mulval_combinations_match=True,
        behavior_checks_passed=True,assumptions_unchanged=True,graph_seconds=build_seconds,
        mulval_validation_seconds=validation_seconds,experiment_seconds=time.perf_counter()-started))
    from report import build_report
    build_report();verify_saved()
    print('Complete:',HERE/'CASE_STUDY.md',flush=True)


def verify_saved():
    graph=read_graph(HERE/'graph');bundle=json.loads((HERE/'assumptions.json').read_text())
    reference=json.loads((HERE/'configs/S1.json').read_text())
    rows=enumerate_all(graph,reference)
    for row in rows:
        target=HERE/'validation'/f"mask_{row['mask']:02d}"
        vg=read_graph(target)[0]
        actual={n['label'] for n in vg.values() if n['type']=='OR'} & set(GOALS)
        assert actual=={g['label'] for g in row['goals'] if g['reachable']}
        assert sha(target/'input.P')==json.loads((target/'meta.json').read_text())['input_sha256']
    for task_path in (HERE/'results').rglob('task.json'):
        task=json.loads(task_path.read_text());result=json.loads(task_path.with_name('result.json').read_text())
        value,_=optimum(enumerate_all(graph,task['config']),task['budget'])
        evaluated=evaluate(graph,task['config'],[r['id'] for r in result['selected_defenses']])
        assert abs(value-result['objective_cost_form'])<1e-6
        assert abs(value-evaluated['objective'])<1e-6
        assert abs(evaluated['attacker_utility']-result['attacker_utility'])<1e-6
    manifest=json.loads((HERE/'manifest.json').read_text())
    assert sha(HERE/'assumptions.json')==manifest['assumptions_sha256']
    for path,h in manifest['input_sha256'].items():assert sha(ROOT/path)==h,path
    for path,h in manifest['generated_input_sha256'].items():assert sha(HERE/path)==h,path
    for path,h in manifest['source_snapshots'].items():assert sha(HERE/'sources'/path)==h,path
    verify_scenario_behavior(json.loads((HERE/'results/budgets.json').read_text()),
                             json.loads((HERE/'results/counterfactuals.json').read_text()))
    print('All scenario inputs, strategies and attacker responses verified.',flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--worker',type=Path)
    parser.add_argument('--report-only',action='store_true');parser.add_argument('--verify-only',action='store_true')
    args=parser.parse_args()
    if args.worker:worker(args.worker)
    elif args.verify_only:verify_saved()
    elif args.report_only:
        from report import build_report
        build_report()
    else:run_experiments()


if __name__=='__main__':
    try:main()
    except Exception as exc:
        if len(sys.argv)==1:
            (HERE/'RUN_FAILED.md').write_text(f'# Run failed\n\nResults unavailable until a successful full rerun.\n\n{type(exc).__name__}: {exc}\n')
        raise
