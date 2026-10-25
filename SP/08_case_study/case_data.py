"""One effort-based reference and three deliberately illustrative cost scenarios."""
REFERENCE_SCALE = 100.0
LABOR_CNY_H = 200.0
BUDGET = 15.0
# Work breakdown order: assess, backup, install, validate.
VULNS = [
 dict(host='h1', service='Apache HTTP', software='apache_http', cve='CVE-2021-42013',
      version='Apache HTTP Server 2.4.50', fix='2.4.51（修复本 CVE 的历史版本）',
      precondition='启用 CGI；Alias 对应路径之外的目录未由 require all denied 保护。',
      remediation='升级 HTTP Server，备份配置，回归 CGI、TLS 与站点访问。',
      source='https://httpd.apache.org/security/vulnerabilities_24.html',
      attack_hours=[0.5,1,0.5], patch_hours=[0.5,0.5,0.5,0.5], downtime=0.1, outage_rate=1000,
      rationale='请求型漏洞；假定已有工具，仍需核查 CGI 与目录条件。维护采用短时服务重启。'),
 dict(host='h2', service='FortiOS VPN', software='fortios_ssl_vpn', cve='CVE-2022-42475',
      version='FortiOS 7.2.2', fix='FortiOS 7.2.3（修复本 CVE 的历史版本）',
      precondition='受影响的 SSL-VPN 服务启用且向 Internet 开放。',
      remediation='按对应固件分支升级，备份配置，安排重启并验证 VPN、路由和认证。',
      source='https://fortiguard.fortinet.com/psirt/FG-IR-22-398',
      attack_hours=[2,4,2], patch_hours=[1,0.5,1,1.5], downtime=0.25, outage_rate=2000,
      rationale='堆内存破坏利用的版本适配和稳定性检查工时高于请求型漏洞；此差异不是 CVSS 自动推导。'),
 dict(host='h3', service='Tomcat', software='tomcat', cve='CVE-2017-12617',
      version='Tomcat 8.5.22', fix='Tomcat 8.5.23（修复本 CVE 的历史版本）',
      precondition='HTTP PUT 启用，例如 DefaultServlet 的 readonly=false；应用可执行上传的 JSP。',
      remediation='升级 Tomcat，备份应用配置，重启并回归应用；主实验不以关闭 PUT 替代补丁。',
      source='https://tomcat.apache.org/security-8.html',
      attack_hours=[1,2,1], patch_hours=[0.5,0.5,0.5,1.5], downtime=0.25, outage_rate=2000,
      rationale='需确认 PUT 配置并适配上传、执行流程；修复后应用兼容性验证占主要工时。'),
 dict(host='h4', service='Debian Redis', software='redis_debian', cve='CVE-2022-0543',
      version='Debian 11 bullseye，redis 5:6.0.16-1+deb11u1', fix='5:6.0.16-1+deb11u2',
      precondition='存在 Debian 特定 Lua 打包问题；从应用主机可调用脚本，不额外要求未建模的凭证。',
      remediation='更新 Debian redis 软件包，备份数据和配置，重启并验证持久化与应用读写。',
      source='https://security-tracker.debian.org/tracker/CVE-2022-0543',
      attack_hours=[0.5,1,0.5], patch_hours=[0.5,1,0.5,1], downtime=0.25, outage_rate=2000,
      rationale='有现成利用思路，仍需确认 Debian 包和脚本权限；修补需数据与持久化回归。'),
 dict(host='h5', service='Windows RDP', software='remote_desktop_services', cve='CVE-2019-0708',
      version='Windows Server 2008 R2 SP1，未安装相应更新', fix='适用的 Microsoft 2019-05 安全更新（如 KB4499175）',
      precondition='RDP 可从应用主机访问，相关安全更新缺失，NLA 关闭。',
      remediation='安装适用的安全更新并重启，验证 RDP、应用及工业管理通路。',
      source='https://www.microsoft.com/en-us/msrc/blog/2019/05/prevent-a-worm-by-updating-remote-desktop-services-cve-2019-0708',
      attack_hours=[2,4,2], patch_hours=[1,0.5,1,1.5], downtime=0.5, outage_rate=1000,
      rationale='假定需要内核内存破坏利用的版本与稳定性适配；Windows 重启和管理通路验证增加维护耗时。'),
 dict(host='h6', service='Modicon M221', software='m221_management', cve='CVE-2018-7798',
      version='Modicon M221（公告列为所有版本）', fix=None,
      precondition='工业控制器管理服务仅从 Windows 管理主机可达；本案例将 TCP/502 作为受控管理通路。',
      remediation='公告建议限制 Port 502 的远程访问、关闭不用的协议；本案例不将缓解写成补丁。',
      source='https://www.cisa.gov/news-events/ics-advisories/icsa-18-324-02',
      attack_hours=[1,2,1], patch_hours=None, downtime=None, outage_rate=None,
      rationale='需确认设备与管理协议并准备配置变更；后果仅为 IPv4 配置修改。'),
]
GOALS = {
 'execCode(h4,redis)': dict(name='Redis', reward=60., loss=200.,
     loss_components_cny={'业务中断：4小时×2000元':8000, '恢复验证与应急处置：60工时×200元':12000},
     reward_note='攻击者对该次资产控制的主观收益估值 6000 元；非黑市价格调查。'),
 'modifyNetworkConfig(h6)': dict(name='Modicon M221', reward=120., loss=1000.,
     loss_components_cny={'业务中断：8小时×10000元':80000, '恢复验证与应急处置：100工时×200元':20000},
     reward_note='攻击者对该次工业配置破坏的主观收益估值 12000 元；不等于防御者损失。'),
}
TOPOLOGY = [('internet','h1','TCP 443'),('internet','h2','TCP 443'),
 ('h1','h3','TCP 8443'),('h2','h3','TCP 8443'),('h3','h4','TCP 6379'),
 ('h3','h5','TCP 3389'),('h5','h6','TCP 502')]


def assumptions():
    import copy
    result = copy.deepcopy(VULNS)
    for v in result:
        v['attack_cost'] = sum(v['attack_hours'])*LABOR_CNY_H/REFERENCE_SCALE
        v['defense_cost'] = (sum(v['patch_hours'])*LABOR_CNY_H + v['downtime']*v['outage_rate'])/REFERENCE_SCALE if v['patch_hours'] else None
    return dict(reference_scale=REFERENCE_SCALE,labor_cny_per_hour=LABOR_CNY_H,main_budget=BUDGET,
                evidence_class='documented vulnerabilities; scenario-estimated economic parameters',
                attack_breakdown=['prepare','adapt','execute_validate'],
                patch_breakdown=['assess','backup','install','validate'],vulnerabilities=result,goals=copy.deepcopy(GOALS))


# Goals, graph, patch eligibility and solver conventions are identical across cases.
# Order is h1...h6; the industrial controller remains unavailable as a patch action.
SCENARIOS = [
    dict(id='S1', title='合理成本基准', title_en='Effort-based reference',
         evidence='effort_based', main_budget=15, focus_budgets=[0,5,10,11,15],
         attack_costs=None, defense_costs=None,
         intent='按公开修复操作拆分工时与停机需求，展示共同中间节点修补的价值。'),
    dict(id='S2', title='预算不足时转移攻击目标', title_en='Redirect under limited budget',
         evidence='illustrative', main_budget=5, focus_budgets=[0,4,5,16,17],
         attack_costs=[4,16,8,4,16,8], defense_costs=[20,24,30,12,5,None],
         intent='使 RDP 补丁先于完全阻断方案可负担，观察攻击目标从控制器转向 Redis。'),
    dict(id='S3', title='攻击成本权衡与防御反效果', title_en='Attack cost and adverse redirection',
         evidence='illustrative', main_budget=5, focus_budgets=[0,5,12,16,17],
         attack_costs=[4,16,8,4,50,30], defense_costs=[20,24,30,5,12,None],
         intent='两个目标都可达时，较低收益的 Redis 可能有更高净收益；只修 Redis 可能将攻击转向损失更大的控制器。'),
    dict(id='S4', title='路径仍可达时的经济威慑', title_en='Deterrence without disconnection',
         evidence='illustrative', main_budget=4, focus_budgets=[0,3,4,28,29],
         attack_costs=[2,120,4,2,5,5], defense_costs=[4,25,30,18,20,None],
         intent='修补低成本入口后仍保留另一入口，但剩余攻击成本超过两个目标收益，攻击者主动放弃。'),
]


def scenario_data():
    import copy
    base=assumptions()
    cases=[]
    for spec in SCENARIOS:
        data=copy.deepcopy(base)
        data.update(copy.deepcopy(spec))
        for index,v in enumerate(data['vulnerabilities']):
            if spec['attack_costs'] is not None:
                v['attack_cost']=float(spec['attack_costs'][index])
                v['defense_cost']=spec['defense_costs'][index]
                # Do not attach estimated labor or economic evidence to designed costs.
                for key in ('attack_hours','patch_hours','downtime','outage_rate','rationale'):
                    v.pop(key,None)
        data['budget_max']=int(sum(v['defense_cost'] or 0 for v in data['vulnerabilities']))
        cases.append(data)
    return cases
