"""Rerun selected frozen-input experiments without overwriting archived results."""
import argparse,json,os,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
ENV={**os.environ,**{k:'1' for k in ['OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','NUMEXPR_NUM_THREADS']},'PYTHONHASHSEED':'0','PYTHONDONTWRITEBYTECODE':'1'}
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--list',action='store_true');p.add_argument('--id');p.add_argument('--experiment');p.add_argument('--output',type=Path,default=ROOT/'reruns');a=p.parse_args()
 index=json.loads((ROOT/'experiment_index.json').read_text())
 selected=[i for i in index if (a.id is None or i['id']==a.id) and (a.experiment is None or i['experiment']==a.experiment)]
 if a.list:
  for i in selected:print(i['id'])
  return
 if not (a.id or a.experiment):p.error('Select --id or --experiment (use --list to inspect IDs).')
 if not selected:p.error('No matching tasks.')
 out=a.output.resolve()
 if out==ROOT or ROOT/'experiments' in [out,*out.parents]:p.error('Output must not overwrite the archived experiments.')
 failures=0
 for item in selected:
  folder=out/item['id'];folder.mkdir(parents=True,exist_ok=False)
  task=json.loads((ROOT/item['task']).read_text());task['result']=str(folder/'result.json')
  for k in ['vertices','arcs','cost_file']:
   if k in task:task[k]=str(ROOT/task[k])
  task['started']=time.perf_counter();taskfile=folder/'task.json';taskfile.write_text(json.dumps(task,indent=2)+'\n')
  kind=item['worker'];limit=task.get('seconds',task.get('limit',60))
  if kind=='anytime':
   cmd=[sys.executable,str(ROOT/'SP/scripts/anytime_worker.py'),'--method',task['method'],'--cost-file',task['cost_file'],'--dataset',task['dataset'],'--vertices',task['vertices'],'--arcs',task['arcs'],'--goals',','.join(map(str,task['goals'])),'--budget','none' if task['budget'] is None else str(task['budget']),'--seed',str(task['seed']),'--seconds',str(limit),'--started',str(task['started']),'--output',str(folder)]
  elif kind=='case':cmd=[sys.executable,str(ROOT/'SP/08_case_study/run_case_study.py'),'--worker',str(taskfile)]
  else:cmd=[sys.executable,str(ROOT/('SP/scripts/budget_comparison_worker.py' if kind=='paired' else 'SP/scripts/worker.py')),'--task',str(taskfile)]
  status='completed';start=time.perf_counter()
  with (folder/'stdout.log').open('w') as log:
   proc=subprocess.Popen(cmd,cwd=ROOT,env=ENV,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   try:proc.wait(timeout=limit+(10 if kind=='case' else 2))
   except subprocess.TimeoutExpired:
    os.killpg(proc.pid,signal.SIGKILL);proc.wait();status='hard_timeout'
  if proc.returncode and status!='hard_timeout':status='failed';failures+=1
  (folder/'meta.json').write_text(json.dumps({'status':status,'returncode':proc.returncode,'wall_seconds':time.perf_counter()-start},indent=2)+'\n')
  print(item['id'],status,flush=True)
 raise SystemExit(bool(failures))
if __name__=='__main__':main()
