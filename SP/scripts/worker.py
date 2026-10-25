"""Isolated fixed-work experiment; imports existing algorithms unchanged."""
import argparse,json,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'baselines')]

def main():
 p=argparse.ArgumentParser();p.add_argument('--task',type=Path,required=True);args=p.parse_args()
 t=json.loads(args.task.read_text());start=time.perf_counter()
 costs=json.loads(Path(t['cost_file']).read_text())
 attack_raw=json.dumps({i:c*t.get('attack_scale',1) for i,c in costs['attack_costs'].items()})
 defense_raw=json.dumps({i:c*t.get('defense_scale',1) for i,c in costs['defense_costs'].items()})
 from baseline_common import add_problem_arguments,load_problem,evaluate_defense_set,attach_benefit
 q=argparse.ArgumentParser();add_problem_arguments(q)
 opts=['--vertices',t['vertices'],'--arcs',t['arcs'],'--goals',','.join(map(str,t['goals'])),'--default-reward',str(t['reward']),'--default-loss',str(t['loss']),'--defense-cost',str(t['defense_cost']),'--attack-cost-source','constant','--default-action-cost',str(t['action_cost']),'--target-closure']
 if t['budget'] is not None:opts.extend(['--budget',str(t['budget'])])
 opts.extend(['--node-attack-costs',attack_raw,'--defense-costs',defense_raw])
 problem=load_problem(q.parse_args(opts));empty=evaluate_defense_set(problem,set(),method='empty');j0=empty['objective_cost_form'];method=t['method']
 if method=='empty':result=empty
 elif method=='random':
  from random_defense_baseline import run_random_baseline
  result=run_random_baseline(problem,t['budget'],50,t['seed'],j0)
 elif method=='ga':
  from ga_defense_baseline import run_ga_baseline
  result=run_ga_baseline(problem,t['budget'],1,64,50,t['seed'],j0)
 elif method=='path_enum':
  from full_path_enumeration_baseline import run_path_enumeration_baseline
  result=run_path_enumeration_baseline(problem,t['budget'],t.get('max_paths',100000),200,j0)
 elif method=='stackelberg':
  import solve_mulval__stackelberg_main as core
  original=core.create_model_backend;models=[]
  def backend(solver,time_limit,mip_gap):
   model,qs=original(solver,max(.01,t['limit']-(time.perf_counter()-t['started'])-1),mip_gap)
   model.setIntParam('parallel/maxnthreads',1);model.setIntParam('randomization/randomseedshift',t['seed']);models.append(model)
   return model,qs
  core.create_model_backend=backend
  result=core.solve_game(problem.vertices,problem.arcs,None,problem.goals,t['reward'],t['loss'],None,None,t['defense_cost'],defense_raw,'vul',t['budget'],'constant',t['action_cost'],0.,attack_raw,None,True,t['limit'],0.,False,'scip',None)
  model=models[0]
  result['model_stats']={'variables':model.getNVars(transformed=False),'constraints':model.getNConss(transformed=False),'dual_bound':model.getDualbound(),'primal_bound':model.getPrimalbound(),'search_nodes':model.getNNodes(),'threads':1}
  attach_benefit(result,j0)
 else:raise ValueError(method)
 if result.get('objective_cost_form') is not None:
  selected={x['id'] for x in result.get('selected_defenses',[])}
  check=evaluate_defense_set(problem,selected,method='validation')
  if abs(check['objective_cost_form']-result['objective_cost_form'])>1e-5:raise RuntimeError('Selected strategy disagrees with independent evaluator')
  result['independent_strategy_check']=True
 result['empty_objective_cost_form']=j0
 result['worker_wall_seconds']=time.perf_counter()-start
 Path(t['result']).write_text(json.dumps(result,indent=2))
if __name__=='__main__':main()
