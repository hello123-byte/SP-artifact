"""Read-only audit of frozen source records; writes only the audit output."""
import csv, json, math, hashlib, sys, statistics, collections, bisect
from pathlib import Path
ROOT=Path(__file__).resolve().parent
import os
os.chdir(ROOT)
def read(p): return json.loads(Path(p).read_text())
def rows(p): return list(csv.DictReader(Path(p).open()))
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def near(a,b): assert math.isclose(float(a),float(b),abs_tol=1e-6,rel_tol=1e-8),(a,b)
graphs={};counts=collections.Counter();checks=[]
def graph(t):
 key=t['vertices']
 if key in graphs:return graphs[key]
 v={int(r[0]):(r[1],r[2]) for r in csv.reader(Path(key).open()) if r}
 arcs=[(int(r[0]),int(r[1])) for r in csv.reader(Path(t['arcs']).open()) if r]
 children={i:[] for i in v};parents={i:[] for i in v}
 for i,j in arcs:children[i].append(j);parents[j].append(i)
 left={i:len(ch) for i,ch in children.items()};order=[i for i in v if not left[i]]
 for i in order:
  for p in parents[i]:
   left[p]-=1
   if left[p]==0:order.append(p)
 assert len(order)==len(v),'cycle'
 assert all(sum(v[j][1]=='OR' for j in children[i])<=1 for i in v if v[i][1]=='AND'),'multi-OR AND'
 graphs[key]=(v,arcs,children,order);return graphs[key]
def eval_task(t,selected):
 v,arcs,ch,order=graph(t);cost=read(t['cost_file']);selected=set(selected)
 ac={int(k):a*t.get('attack_scale',1) for k,a in cost['attack_costs'].items()}
 dc={int(k):a*t.get('defense_scale',1) for k,a in cost['defense_costs'].items()}
 assert selected<=dc.keys();spend=sum(dc[i] for i in selected)
 assert t['budget'] is None or spend<=t['budget']+1e-6
 c={}
 for i in order:
  kind=v[i][1]
  c[i]=(math.inf if i in selected else 0) if kind=='LEAF' else ((ac.get(i,0)+sum(c[j] for j in ch[i])) if kind=='AND' else min(c[j] for j in ch[i]))
 utility=max([0]+[t.get('reward',1000)-c[g] for g in t['goals']]);loss=t.get('loss',1000) if utility>1e-7 else 0
 return spend+loss,spend,utility
hash_cache={}
def check_inputs(t):
 for key in ('vertices','arcs','cost_file'):
  expected=t['cost_sha256' if key=='cost_file' else key+'_sha256'];p=t[key]
  if p not in hash_cache:hash_cache[p]=sha(p)
  assert hash_cache[p]==expected,(p,'hash mismatch')

def check_run(t,folder):
 check_inputs(t);m=read(folder/'meta.json');assert m['status'] in ('completed','hard_timeout'),m['status']
 counts['fixed_tasks']+=1
 if not (folder/'result.json').exists():
  assert m['status']=='hard_timeout';counts['timeouts_without_result']+=1;return None
 r=read(folder/'result.json')
 if r.get('objective_cost_form') is not None:
  ids=[i['id'] for i in r['selected_defenses']];assert len(ids)==len(set(ids))
  obj,spend,u=eval_task(t,ids);near(obj,r['objective_cost_form']);counts['independently_checked_strategies']+=1
  if 'attacker_utility' in r:near(u,r['attacker_utility'])
  near(eval_task(t,[])[0],r['empty_objective_cost_form'])
  if t['method']=='random':
   trials=r['trial_summaries'];assert len(trials)==50
   avg=statistics.fmean(x['objective_cost_form'] for x in trials)
   near(avg,r.get('comparison_objective',r['objective_mean']))
   if t['budget'] is not None:assert all(x['defense_cost']<=t['budget']+1e-6 for x in trials)
   counts['random_sample_means_checked']+=1
 return r


def main():
 manifest=read(ROOT/'MANIFEST.json')
 for name,digest in manifest['files'].items():assert sha(ROOT/name)==digest,('checksum',name)
 index=read(ROOT/'experiment_index.json');table_results={};anytime={}
 sys.path.insert(0,str(ROOT/'SP/08_case_study'))
 import run_case_study as cs
 from case_data import scenario_data
 cg=cs.read_graph(cs.HERE/'graph');configs={};enums={}
 for sc in scenario_data():
  config,_=cs.prepare_config(sc,cg);configs[sc['id']]=config;enums[sc['id']]=cs.enumerate_all(cg,config)
 for item in index:
  folder=ROOT/item['folder'];t=read(ROOT/item['task']);kind=item['worker']
  if kind=='case':
   sc=t['key'].split('/')[0];r=read(folder/'result.json');ids=[i['id'] for i in r['selected_defenses']]
   near(cs.evaluate(cg,configs[sc],ids)['objective'],r['objective_cost_form']);near(cs.optimum(enums[sc],t['budget'])[0],r['objective_cost_form']);assert r['status']=='optimal';counts['case_study_solves']+=1
  elif kind=='anytime':
   check_inputs(t);m=read(folder/'meta.json');ts=[0.];ys=[0.];best=1000.;lines=(folder/'trace.jsonl').read_text().splitlines()
   for i,line in enumerate(lines):
    try:e=json.loads(line)
    except json.JSONDecodeError:assert i==len(lines)-1 and m['status']=='hard_timeout';continue
    if e['kind']!='improvement' or e['time']>100:continue
    obj,spend,u=eval_task(t,e['selected_ids']);near(obj,e['objective']);near((1000-obj)/1000,e['benefit']);assert obj<best-1e-7 and e['time']>=ts[-1];best=obj;ts.append(e['time']);ys.append(e['benefit']);counts['anytime_events']+=1
   if (folder/'result.json').exists():near(read(folder/'result.json')['objective'],best)
   anytime[(item['experiment'],t['dataset'],t['method'],t['seed'],t['budget'])]=(ts,ys);counts['anytime_tasks']+=1
  else:
   r=check_run(t,folder)
   if item['experiment']=='tables':table_results[(t['dataset'],t['budget_mode'],t['method'],t['seed'])]=r
 datasets=['D64','D244','D1045','D2822','D6330','D11026']
 for row in rows(ROOT/'tables/table2.csv'):
  d=datasets[int(row['Instance'][2:])-1];mode='budget_300' if row['Budget']=='300' else 'unbudgeted'
  for label,method in {'No Defense':'empty','Random':'random','Path Enum.':'path_enum','GA':'ga','Proposed':'stackelberg'}.items():
   group=[table_results[(d,mode,method,s)] for s in (range(7,17) if method=='ga' else [7])]
   values=[(1000-(r['comparison_objective'] if method=='random' else r['objective_cost_form']))/1000 for r in group if r and r.get('objective_cost_form') is not None]
   if values:assert row[label]==f'{statistics.fmean(values):.3f}'
   elif row[label]=='EL':assert all(r and r['status']=='skipped_limit' for r in group)
   else:assert row[label]=='TL' and all(r is None or r['status'] in ('timelimit','time_limit') for r in group)
   counts['table2_cells']+=1
 for row in rows(ROOT/'tables/table3.csv'):
  d=datasets[int(row['Instance'][2:])-1];mode='budget_300' if row['Budget']=='300' else 'unbudgeted';rs=[table_results[(d,mode,'stackelberg',s)] for s in [7,8,9]]
  assert all(r['status']=='optimal' and r['relative_gap']==0 for r in rs)
  for col,field in [('Build (s)','build_mip'),('Solve (s)','optimize'),('Total (s)','total_solve_game')]:assert row[col]==f"{statistics.fmean(r['timings_seconds'][field] for r in rs):.3f}"
  counts['table3_rows']+=1
 for filename,exp,budget in [('figure5_AG1_AG5.csv','anytime_budget300',300),('anytime_unbudgeted_supplement.csv','anytime_unbudgeted_supplement',None),('figure5_AG6.csv','anytime_AG6',300)]:
  for rr in rows(ROOT/'tables'/filename):
   b=None if rr.get('condition')=='unbudgeted' else budget;vals=[]
   for seed in [7,8,9]:
    ts,ys=([0.],[0.]) if rr['method']=='empty' else anytime[(exp,rr['dataset'],rr['method'],seed,b)]
    vals.append(ys[bisect.bisect_right(ts,float(rr['seconds']))-1])
   near(rr['mean_best_benefit'],statistics.fmean(vals));near(rr['std'],statistics.pstdev(vals));counts['anytime_summary_rows']+=1
 print(json.dumps({'status':'passed','tasks':len(index),'counts':dict(counts),'note':'Verifies archived data and strategies; does not rerun or certify historical wall-clock timings.'},indent=2))
if __name__=='__main__':main()
