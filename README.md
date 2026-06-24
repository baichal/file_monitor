# 文件系统监控与清理工具 (Python 版)

一个功能完整的 Linux 文件系统监控与清理工具，用 Python + watchdog 实现。

## 设计目标与完成度

| 设计目标 | 完成度 | 核心功能 |
|---------|--------|---------|
| **软件安装测试** | ✅ 95% | 状态快照对比、apt purge 彻底清理、用户配置清理、依赖清理 |
| **应用程序调试** | ✅ 85% | 按包分组、文件时间线、进程关联、配置追踪 |
| **系统安全监控** | ✅ 90% | 全事件监控、四级风险评估、实时告警、敏感文件保护 |
| **系统配置管理** | ✅ 90% | sysctl 备份恢复、/etc 配置备份、多版本管理、自动回滚 |

## 系统要求

- Linux (Debian/Ubuntu, CentOS/RHEL)
- Python 3.8+
- root 权限
- watchdog 库

## 快速开始

### 安装依赖

```bash
# Debian/Ubuntu
sudo apt install python3-watchdog

# 或 pip 安装
sudo pip3 install watchdog
```

### 查看帮助

```bash
sudo python3 file_monitor.py --help
```

### 交互式菜单（推荐新手）

```bash
sudo python3 file_monitor.py
# 或
sudo python3 file_monitor.py menu
```

## 功能详解

### 1. 软件安装测试

**工作流程：**
```bash
# 1. 安装前捕获状态
sudo python3 file_monitor.py capture -n before_install

# 2. 安装软件
sudo apt install nginx

# 3. 安装后捕获状态
sudo python3 file_monitor.py capture -n after_install

# 4. 对比差异
sudo python3 file_monitor.py diff before_install after_install

# 5. 彻底卸载（含配置、用户数据）
sudo python3 file_monitor.py remove nginx
```

**彻底清理包含：**
- ✅ `apt purge` 移除程序和配置
- ✅ `apt autoremove` 清理无用依赖
- ✅ 停止并禁用 systemd 服务
- ✅ 清理 `~/.config/`、`~/.local/share/` 等用户配置
- ✅ 清理残留配置文件

### 2. 应用程序调试

```bash
# 查看所有事件
sudo python3 file_monitor.py events -l 100

# 按类型过滤
sudo python3 file_monitor.py events -t created
sudo python3 file_monitor.py events -t modified
sudo python3 file_monitor.py events -t deleted

# 按路径过滤
sudo python3 file_monitor.py events -p /etc

# 查看追踪的软件包
sudo python3 file_monitor.py packages
```

### 3. 系统安全监控

**风险等级：**
- 🔴 `critical` - /etc/passwd, /etc/shadow, /etc/sudoers 等
- 🟠 `high` - /etc/*, /usr/bin/*, systemd 服务等
- 🟡 `medium` - Docker, 用户 SSH 配置
- 🟢 `low` - 普通文件

```bash
# 启动监控守护进程
sudo python3 file_monitor.py start

# 查看状态
sudo python3 file_monitor.py status

# 查看安全告警
sudo python3 file_monitor.py alerts

# 停止监控
sudo python3 file_monitor.py stop
```

### 4. 系统配置管理

```bash
# 保存 sysctl 配置
sudo python3 file_monitor.py config save -t sysctl -n my_sysctl

# 保存 /etc 关键配置
sudo python3 file_monitor.py config save -t etc -n my_etc_backup

# 列出所有备份
sudo python3 file_monitor.py config list

# 恢复配置
sudo python3 file_monitor.py config restore -t sysctl -n my_sysctl

# 删除备份
sudo python3 file_monitor.py config delete -n my_sysctl
```

## 命令总览

### 监控控制
| 命令 | 说明 |
|------|------|
| `start` | 启动守护进程 |
| `stop` | 停止守护进程 |
| `status` | 查看状态 |

### 状态管理
| 命令 | 说明 |
|------|------|
| `capture -n NAME` | 捕获系统状态快照 |
| `diff S1 S2` | 比较两个状态 |
| `states` | 列出所有状态 |

### 清理管理
| 命令 | 说明 |
|------|------|
| `remove PACKAGE` | 彻底卸载软件包 |
| `clean` | 交互式清理向导 |
| `packages` | 查看追踪的包 |

### 安全监控
| 命令 | 说明 |
|------|------|
| `alerts` | 查看安全告警 |
| `events` | 查看事件记录 |

### 配置管理
| 命令 | 说明 |
|------|------|
| `config save -t TYPE -n NAME` | 保存配置备份 |
| `config restore -t TYPE -n NAME` | 恢复配置 |
| `config list` | 列出备份 |
| `config delete -n NAME` | 删除备份 |

### 白名单
| 命令 | 说明 |
|------|------|
| `whitelist list` | 查看白名单 |
| `whitelist add -p PATH` | 添加白名单 |
| `whitelist remove -p PATH` | 移除白名单 |
| `whitelist clear` | 清空白名单 |

### 开机自启
| 命令 | 说明 |
|------|------|
| `autostart enable` | 启用开机自启 |
| `autostart disable` | 禁用开机自启 |
| `autostart status` | 查看自启状态 |

## 数据存储

所有数据存储在 `/var/lib/file_monitor/`：

| 文件/目录 | 内容 |
|-----------|------|
| `events.jsonl` | 文件系统事件记录（JSON Lines） |
| `alerts.jsonl` | 安全告警记录 |
| `packages.json` | 软件包追踪记录 |
| `whitelist.json` | 白名单配置 |
| `states/` | 系统状态快照 |
| `config_backups/` | 配置备份 |
| `monitor.log` | 运行日志 |
| `monitor.pid` | 进程 PID |
| `config.json` | 主配置文件 |

## 配置文件

配置文件路径：`/var/lib/file_monitor/config.json`

```json
{
  "monitor_user_dirs": true,
  "alert_on_sensitive_changes": true,
  "max_events": 100000,
  "retention_days": 30,
  "ignore_patterns": [
    "/proc", "/sys", "/dev", "/run", "/tmp",
    "/var/log", "/var/cache"
  ],
  "monitor_paths": ["/usr", "/var", "/opt", "/etc"]
}
```

## 架构说明

### 核心模块

- **Config** - 配置管理
- **LogManager** - 日志管理（含自动轮转）
- **EventStore** - 事件存储与查询
- **WhitelistManager** - 白名单管理
- **SecurityMonitor** - 安全监控与告警
- **PackageManager** - 软件包追踪与清理
- **DockerManager** - Docker 容器管理
- **StateManager** - 系统状态快照与对比
- **ConfigBackupManager** - 配置备份与恢复
- **MonitorHandler** - 文件系统事件处理器
- **DaemonService** - 守护进程服务
- **InteractiveCleaner** - 交互式清理向导
- **InteractiveMenu** - 交互式菜单界面

### 事件类型

- `created` - 文件/目录创建
- `deleted` - 文件/目录删除
- `modified` - 文件/目录修改
- `moved_from` - 移出
- `moved_to` - 移入

### 守护进程线程

1. **主线程** - watchdog 事件循环
2. **包监控线程** - 每 30 秒检测包安装/卸载
3. **清理线程** - 每小时轮转日志、清理旧事件

## 从 Bash 版本迁移

Python 版本与 Bash 版本数据格式不兼容，建议：

```bash
# 1. 停止旧版本
sudo ./file_monitor.sh stop

# 2. 清理旧数据（可选）
sudo rm -rf /var/lib/file_monitor/*

# 3. 启动新版本
sudo python3 file_monitor.py start
```

## 性能说明

- 文件监控使用 `watchdog` 库（基于 inotify），性能优异
- 状态捕获使用 `os.walk`，初次扫描可能较慢（取决于文件数）
- 事件使用 JSON Lines 格式存储，支持流式读写
- 自动轮转和定期清理，避免磁盘空间耗尽

## 注意事项

- 必须以 root 权限运行
- 监控大量小文件会占用较多内存
- 重要操作前建议先捕获状态快照
- 删除操作不可逆，请谨慎使用

## 许可证

MIT License
