"""Semantic checks independent of the MIP and its graph-cost recurrence."""
import copy, itertools, math, unittest
from pathlib import Path
from case_data import assumptions, scenario_data
import run_case_study as case


class CaseStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=assumptions()
        cls.graph=case.read_graph(case.HERE/'graph')
        cls.config,cls.mapping=case.prepare_config(cls.data,cls.graph)
        cls.hosts={m['host']:m for m in cls.mapping.values()}

    def test_four_explicit_attack_chains_match_all_32_masks(self):
        attack={v['host']:v['attack_cost'] for v in self.data['vulnerabilities']}
        chains={'Redis':[('h1','h3','h4'),('h2','h3','h4')],
                'Modicon M221':[('h1','h3','h5','h6'),('h2','h3','h5','h6')]}
        for row in case.enumerate_all(self.graph,self.config):
            blocked={h for h,m in self.hosts.items() if m['leaf'] in row['selected_defenses']}
            for goal in row['goals']:
                possible=[sum(attack[h] for h in path) for path in chains[goal['name']] if not blocked.intersection(path)]
                self.assertEqual(goal['reachable'],bool(possible))
                self.assertEqual(goal['min_attack_cost'],min(possible) if possible else None)

    def test_no_charge_for_auxiliary_rules_and_no_controller_patch(self):
        paid={int(i) for i,n in self.config['nodes'].items() if n['attack_cost']}
        self.assertEqual(paid,{i for m in self.mapping.values() for i in m['actions']})
        with self.assertRaises(AssertionError):case.evaluate(self.graph,self.config,[self.hosts['h6']['leaf']])
        self.assertEqual([v['defense_cost'] for v in self.data['vulnerabilities']], [5,13,11,11,13,None])

    def test_zero_utility_and_defender_favorable_tie(self):
        config=copy.deepcopy(self.config)
        for g in config['goals'].values():g['reward']=16 if g['name']=='Redis' else 36
        self.assertEqual(case.evaluate(self.graph,config,[])['attacker_response'],'No attack')
        for g in config['goals'].values():g['reward']+=10
        row=case.evaluate(self.graph,config,[])
        self.assertEqual(row['attacker_response'],'Redis')
        self.assertEqual(row['remaining_loss'],200)

    def test_three_minimal_cuts_and_budget_threshold(self):
        rows=case.enumerate_all(self.graph,self.config)
        cuts=[r for r in rows if not any(g['reachable'] for g in r['goals'])]
        minimal=[r for r in cuts if not any(set(s['selected_defenses'])<set(r['selected_defenses']) for s in cuts)]
        self.assertEqual(sorted(r['defense_cost'] for r in minimal),[11,18,24])
        self.assertEqual(case.optimum(rows,10)[0],1000)
        self.assertEqual(case.optimum(rows,11)[0],11)
        self.assertEqual(case.optimum(rows,None)[0],11)

    def test_node_mapping_survives_relabeling(self):
        v,a,ch,order=self.graph
        relabel={i:1000+len(v)-i for i in v}
        altered=({relabel[i]:{**node,'id':relabel[i]} for i,node in v.items()},
                 [(relabel[x],relabel[y]) for x,y in a],
                 {relabel[i]:[relabel[j] for j in deps] for i,deps in ch.items()},
                 [relabel[i] for i in order])
        config,mapping=case.prepare_config(self.data,altered)
        self.assertEqual(case.optimum(case.enumerate_all(altered,config),15)[0],11)
        for c,m in mapping.items():self.assertEqual(m['leaf'],relabel[self.mapping[c]['leaf']])

    def test_cvss_base_scores_match_vectors(self):
        scores=case.cvss_data(self.data)
        for c,m in scores.items():
            v=dict(x.split(':') for x in m['vector'].split('/')[1:])
            self.assertEqual((v['AV'],v['PR'],v['UI']),('N','N','N'))
            impact_map={'N':0.,'L':.22,'H':.56}
            iss=1-math.prod(1-impact_map[v[k]] for k in ('C','I','A'))
            impact=6.42*iss if v['S']=='U' else 7.52*(iss-.029)-3.25*(iss-.02)**15
            exploitability=8.22*.85*({'L':.77,'H':.44}[v['AC']])*.85*.85
            raw=min(10,(impact+exploitability)*(1 if v['S']=='U' else 1.08))
            self.assertAlmostEqual(math.ceil(raw*10-1e-9)/10,m['score'],msg=c)



    def test_designed_cost_scenarios_produce_distinct_responses(self):
        rows=[];counterfactuals=[]
        for scenario in scenario_data():
            config,mapping=case.prepare_config(scenario,self.graph)
            enumeration=case.enumerate_all(self.graph,config)
            for budget in scenario['focus_budgets']:
                _,best=case.optimum(enumeration,budget)
                rows.append(dict(scenario=scenario['id'],budget=budget,**case.attach_names(best[0],mapping)))
            redis=next(m['leaf'] for m in mapping.values() if m['host']=='h4')
            counterfactuals.append(dict(scenario=scenario['id'],policy='patch_redis_only',
                **case.attach_names(case.evaluate(self.graph,config,[redis]),mapping)))
        case.verify_scenario_behavior(rows,counterfactuals)

    def test_all_cost_sets_match_explicit_chain_costs(self):
        chains={'Redis':[('h1','h3','h4'),('h2','h3','h4')],
                'Modicon M221':[('h1','h3','h5','h6'),('h2','h3','h5','h6')]}
        for scenario in scenario_data():
            config,mapping=case.prepare_config(scenario,self.graph)
            attack={v['host']:v['attack_cost'] for v in scenario['vulnerabilities']}
            for row in case.enumerate_all(self.graph,config):
                blocked={m['host'] for m in mapping.values() if m['leaf'] in row['selected_defenses']}
                for g in row['goals']:
                    possible=[sum(attack[h] for h in path) for path in chains[g['name']] if not blocked.intersection(path)]
                    self.assertEqual(g['min_attack_cost'],min(possible) if possible else None)
                    if possible:self.assertAlmostEqual(g['utility'],g['reward']-min(possible))

if __name__=='__main__':unittest.main()
