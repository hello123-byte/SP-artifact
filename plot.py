"""Regenerate publication figures from audited numeric summaries."""
import csv
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
ROOT=Path(__file__).resolve().parent
plt.rcParams.update({'font.family':'DejaVu Serif','font.size':9,'pdf.fonttype':42})
def rows(name):return list(csv.DictReader((ROOT/'tables'/name).open()))
def save(fig,name):
 out=ROOT/'figures';out.mkdir(exist_ok=True)
 fig.savefig(out/(name+'.png'),dpi=220,bbox_inches='tight')
 fig.savefig(out/(name+'.pdf'),bbox_inches='tight',metadata={'Creator':None,'Producer':None,'CreationDate':None,'ModDate':None,'Author':None})
 plt.close(fig)
def main():
 data=rows('figure3.csv');fig,axes=plt.subplots(1,4,figsize=(13,3),layout='constrained')
 for ax,factor,xlabel in zip(axes,['attack_scale','defense_scale','budget','loss'],['Attack-cost multiplier','Defense-cost multiplier','Defense budget','Target loss']):
  rs=sorted([r for r in data if r['factor']==factor],key=lambda r:float(r['factor_value']));x=[float(r['factor_value']) for r in rs]
  if factor=='attack_scale':
   ax.plot(x,[float(r['empty_attacker_utility']) for r in rs],'o-',label='No defense',markersize=3)
   ax.plot(x,[float(r['attacker_utility']) for r in rs],'s-',label='Proposed',markersize=3);ax.set_ylabel('Attacker utility');ax.legend(frameon=False)
  else:ax.plot(x,[float(r['benefit']) for r in rs],'s-',markersize=3);ax.set_ylabel('Defense benefit');ax.set_ylim(-.03,1.03)
  ax.set_xlabel(xlabel)
 fig.suptitle('AG3 sensitivity (base budget 300, cost replicate 1)');save(fig,'figure3_sensitivity')
 styles={'empty':('No defense','#777777','o'),'random':('Random','#E69F00','o'),'ga':('GA','#009E73','D'),'path_enum':('Path enumeration','#CC79A7','^'),'stackelberg':('Proposed','#0072B2','s')}
 fig,ax=plt.subplots(figsize=(6,4),layout='constrained');data=rows('figure4.csv')
 for method,(label,color,marker) in styles.items():
  rs=sorted([r for r in data if r['method']==method],key=lambda r:float(r['budget']))
  ax.plot([float(r['budget']) for r in rs],[float(r['benefit_mean']) if r['benefit_mean'] else float('nan') for r in rs],label=label,color=color,marker=marker,markersize=3)
 ax.set(xlabel='Defense budget',ylabel='Mean defense benefit',title='AG3: 60 s per task');ax.legend(frameon=False,ncol=3,fontsize=7);save(fig,'figure4_budget')
 fig,axes=plt.subplots(2,3,figsize=(12,7),layout='constrained');data=rows('figure5_AG1_AG5.csv');new=rows('figure5_AG6.csv')
 for n,(ax,ds) in enumerate(zip(axes.flat,['D64','D244','D1045','D2822','D6330','D11026']),1):
  for method,(label,color,marker) in styles.items():
   rs=[r for r in (new if n==6 else data) if r['dataset']==ds and r['method']==method and r.get('condition','budget_300')=='budget_300']
   rs.sort(key=lambda r:float(r['seconds']));ax.step([float(r['seconds']) for r in rs],[float(r['mean_best_benefit']) for r in rs],where='post',color=color,label=label)
  if n==6:
   rs=[r for r in new if r['condition']=='unbudgeted' and r['method']=='stackelberg'];rs.sort(key=lambda r:float(r['seconds']))
   ax.step([float(r['seconds']) for r in rs],[float(r['mean_best_benefit']) for r in rs],where='post',color='#0072B2',linestyle='--',label='Proposed, unbudgeted')
  ax.set_xscale('symlog',linthresh=.02);ax.set(xlim=(0,100),ylim=(-.03,1.03),xlabel='Elapsed wall time (s)',ylabel='Best benefit so far',title=f'AG{n}: budget 300'+(' + unbudgeted Proposed' if n==6 else ''));ax.legend(frameon=False,fontsize=6,ncol=2)
 save(fig,'figure5_anytime_budget_explicit')
 print('Regenerated Figures 3, 4 and 5 with explicit conditions and metadata removed.')
if __name__=='__main__':main()
