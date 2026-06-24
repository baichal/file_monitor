# 文件系统监控与清理工具

这是一个用 Python 重构的文件系统监控与清理工具，用于：
- **软件安装测试**：安装新软件后，可以彻底清理所有相关文件（包括配置文件和用户配置）
- **应用程序调试**：跟踪应用程序产生的文件，支持按应用分组查看
- **系统安全监控**：实时监控文件系统变化，对敏感文件变更提供告警机制
- **系统配置管理**：保存和恢复系统参数（sysctl、/etc 配置），支持版本管理

## 与原 Bash 版本的对比

| 功能 | Bash 版本 | Python 版本 |
|------|-----------|-------------|
| 初始状态对比 | ❌ 不支持 | ✅ 支持 `diff` 命令 |
| 软件包彻底清理 | ❌ 只用 remove | ✅ 使用 purge + 清理用户配置 |
| 用户配置监控 | ❌ /home 被排除 | ✅ 可配置监控 |
| 文件修改监控 | ❌ 只监控创建/删除 | ✅ 监控所有事件类型 |
| 安全告警 | ❌ 无 | ✅ 实时告警 + 风险等级 |
| sysctl 保存 | ❌ 有 bug | ✅ 正确保存和恢复 |
| /etc 配置管理 | ❌ 无 | ✅ 支持备份恢复 |
| 事件分组 | ❌ 无 | ✅ 按包、类型分组 |
| 状态版本管理 | ❌ 无 | ✅ 多版本状态快照 |

## 系统要求

- Linux 操作系统（Debian/Ubuntu 或 RedHat/CentOS）
- Python 3.8+
- root 权限
- watchdog 库

## 安装

### 安装依赖

```bash
# Debian/Ubuntu
sudo apt install python3-watchdog

# 或使用 pip
pip3 install watchdog
```

### 安装工具

```bash
sudo python3 file_monitor.py start
```

## 使用方法

### 基本命令

```bash
# 启动监控守护进程
sudo python3 file_monitor.py start

# 停止监控
sudo python3 file_monitor.py stop

# 查看状态
sudo python3 file_monitor.py status
```

### 软件安装测试流程

```bash
# 1. 安装前捕获系统状态
sudo python3 file_monitor.py capture -n before_install

# 2. 安装软件
sudo apt install nginx

# 3. 安装后捕获状态
sudo python3 file_monitor.py capture -n after_install

# 4. 查看差异（新增的文件和配置）
sudo python3 file_monitor.py diff before_install after_install

# 5. 如果决定卸载，彻底清理
sudo python3 file_monitor.py remove nginx

# 6. 验证清理结果
sudo python3 file_monitor.py diff before_install current
```

### 应用程序调试

```bash
# 查看事件列表
sudo python3 file_monitor.py events -l 50

# 查看特定路径的事件
sudo python3 file_monitor.py events -p /var/log

# 查看特定类型的事件
sudo python3 file_monitor.py events -t created

# 查看追踪的软件包
sudo python3 file_monitor.py packages
```

### 系统安全监控

```bash
# 查看安全告警
sudo python3 file_monitor.py alerts

# 查看高风险事件
sudo python3 file_monitor.py events -t modified -p /etc
```

### 系统配置管理

```bash
# 保存 sysctl 配置
sudo python3 file_monitor.py config save -n my_sysctl -t sysctl

# 保存 /etc 配置
sudo python3 file_monitor.py config save -n my_etc -t etc

# 保存所有配置
sudo python3 file_monitor.py config save -n backup_all

# 列出所有备份
sudo python3 file_monitor.py config list

# 恢复配置
sudo python3 file_monitor.py config restore -n my_sysctl -t sysctl
```

### 白名单管理

```bash
# 查看白名单
sudo python3 file_monitor.py whitelist list

# 添加到白名单
sudo python3 file_monitor.py whitelist add -p /var/www/html -r "网站目录"

# 从白名单移除
sudo python3 file_monitor.py whitelist remove -p /var/www/html

# 清空白名单
sudo python3 file_monitor.py whitelist clear
```

### 状态管理

```bash
# 列出所有保存的状态
sudo python3 file_monitor.py states

# 捕获当前状态
sudo python3 file_monitor.py capture -n my_snapshot

# 比较两个状态
sudo python3 file_monitor.py diff state1 state2
```

## 配置文件

配置文件位于 `/var/lib/file_monitor/config.json`：

```json
{
  "monitor_user_dirs": true,      // 是否监控用户目录（~/.config 等）
  "alert_on_sensitive_changes": true,  // 安全敏感文件变更告警
  "max_events": 100000,           // 最大事件记录数
  "retention_days": 30            // 事件保留天数
}
```

## 数据存储

所有数据存储在 `/var/lib/file_monitor/`：

| 文件 | 内容 |
|------|------|
| `events.jsonl` | 文件系统事件记录 |
| `packages.json` | 软件包追踪记录 |
| `states/` | 系统状态快照 |
| `config_backups/` | 配置备份 |
| `whitelist.json` | 白名单 |
| `monitor.log` | 日志 |

## 风险等级

系统自动评估文件变更的风险等级：

| 等级 | 触发条件 |
|------|---------|
| critical | /etc/passwd, /etc/shadow, /etc/sudoers 等关键安全文件 |
| high | /etc/*, /usr/bin/*, /usr/sbin/*, systemd 服务 |
| medium | Docker 相关, 用户 SSH 配置 |
| low | 其他文件 |

## 命令完整列表

```
start              启动监控守护进程
stop               停止监控
status             查看状态
capture            捕获系统状态
diff               比较两个状态
clean              清理新增项目
packages           查看追踪的软件包
remove             彻底移除软件包
alerts             查看安全告警
events             查看事件列表
config             系统配置管理
whitelist          白名单管理
states             列出所有保存的状态
```

## 从 Bash 版本迁移

Python 版本与 Bash 版本的数据格式不同，建议：

1. 停止 Bash 版本监控
2. 清理旧数据（可选）
3. 启动 Python 版本

```bash
# 停止旧版本
sudo ./file_monitor.sh stop

# 启动新版本
sudo python3 file_monitor.py start
```

## 注意事项

- 需要 root 权限运行
- 监控大量文件可能消耗较多内存
- 建议定期清理旧事件数据
- 重要操作前先捕获状态快照

## 许可证

MIT License