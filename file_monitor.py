#!/usr/bin/env python3
"""
文件系统监控与清理工具 - Python 重构版

设计目标：
- 软件安装测试：彻底清理软件及其所有相关文件
- 应用程序调试：跟踪应用产生的文件，支持按应用分组
- 系统安全监控：实时监控文件变化，提供告警机制
- 系统配置管理：保存和恢复系统参数，支持版本管理
"""

import os
import sys
import json
import time
import hashlib
import subprocess
import argparse
import signal
import logging
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from threading import Thread, Event
import queue

# 尝试导入 watchdog
try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler,
        FileCreatedEvent,
        FileDeletedEvent,
        FileModifiedEvent,
        FileMovedEvent,
        DirCreatedEvent,
        DirDeletedEvent,
        DirModifiedEvent,
        DirMovedEvent,
    )
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("警告: watchdog 未安装，将使用 inotify 备用方案")
    print("建议安装: pip install watchdog")

# 常量定义
BASE_DIR = Path("/var/lib/file_monitor")
CONFIG_FILE = BASE_DIR / "config.json"
STATE_DIR = BASE_DIR / "states"
EVENTS_FILE = BASE_DIR / "events.jsonl"
PACKAGES_FILE = BASE_DIR / "packages.json"
WHITELIST_FILE = BASE_DIR / "whitelist.json"
PID_FILE = BASE_DIR / "monitor.pid"
LOG_FILE = BASE_DIR / "monitor.log"

# 默认忽略模式（这些目录不监控）
DEFAULT_IGNORE_PATTERNS = [
    "/proc", "/sys", "/dev", "/run", "/tmp",
    "/var/log", "/var/cache", "/var/lib/file_monitor",
]

# 用户配置目录（需要监控）
USER_CONFIG_DIRS = [
    "/home",  # 用户配置文件
    "/root",  # root 用户配置
]

# 安全敏感路径
SECURITY_SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/crontab",
    "/etc/systemd/system", "/usr/bin", "/usr/sbin",
    "/bin", "/sbin",
]


@dataclass
class Config:
    """配置类"""
    base_dir: str = str(BASE_DIR)
    log_file: str = str(LOG_FILE)
    events_file: str = str(EVENTS_FILE)
    packages_file: str = str(PACKAGES_FILE)
    whitelist_file: str = str(WHITELIST_FILE)
    ignore_patterns: List[str] = field(default_factory=lambda: DEFAULT_IGNORE_PATTERNS.copy())
    monitor_user_dirs: bool = True  # 是否监控用户目录
    alert_on_sensitive_changes: bool = True  # 安全敏感文件变更告警
    max_events: int = 100000  # 最大事件记录数
    log_rotation_size: int = 10 * 1024 * 1024  # 10MB
    retention_days: int = 30  # 事件保留天数

    def save(self):
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> Config:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE) as f:
                data = json.load(f)
                return cls(**data)
        return cls()


@dataclass
class FileEvent:
    """文件事件记录"""
    timestamp: str
    event_type: str  # created, deleted, modified, moved
    path: str
    is_directory: bool
    size: Optional[int] = None
    checksum: Optional[str] = None  # 文件 MD5
    process_info: Optional[Dict] = None  # 创建进程信息
    package: Optional[str] = None  # 所属软件包
    risk_level: str = "low"  # low, medium, high, critical
    notes: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class PackageRecord:
    """软件包安装记录"""
    name: str
    install_time: str
    files: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    user_configs: List[str] = field(default_factory=list)  # ~/.config 等
    services: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    removed: bool = False
    remove_time: Optional[str] = None


@dataclass
class SystemState:
    """系统状态快照"""
    timestamp: str
    files: Dict[str, Dict] = field(default_factory=dict)  # path -> {size, checksum, mtime}
    packages: List[str] = field(default_factory=list)
    sysctl: Dict[str, str] = field(default_factory=dict)
    services: Dict[str, str] = field(default_factory=dict)  # name -> status
    config_version: str = ""


class Logger:
    """日志管理器"""
    
    def __init__(self, config: Config):
        self.config = config
        self._setup_logging()
    
    def _setup_logging(self):
        log_path = Path(self.config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger("file_monitor")
    
    def info(self, msg: str):
        self.logger.info(msg)
    
    def warning(self, msg: str):
        self.logger.warning(msg)
    
    def error(self, msg: str):
        self.logger.error(msg)
    
    def debug(self, msg: str):
        self.logger.debug(msg)
    
    def critical(self, msg: str):
        self.logger.critical(msg)


class EventStore:
    """事件存储管理器"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.events_file = Path(config.events_file)
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = queue.Queue()  # 简单的锁机制
    
    def add_event(self, event: FileEvent):
        """添加事件到存储"""
        try:
            with open(self.events_file, 'a') as f:
                f.write(event.to_json() + '\n')
            self._check_rotation()
        except Exception as e:
            self.logger.error(f"写入事件失败: {e}")
    
    def get_events(self, 
                   start_time: Optional[str] = None,
                   end_time: Optional[str] = None,
                   event_type: Optional[str] = None,
                   path_prefix: Optional[str] = None,
                   package: Optional[str] = None,
                   risk_level: Optional[str] = None,
                   limit: int = 1000) -> List[FileEvent]:
        """查询事件"""
        events = []
        if not self.events_file.exists():
            return events
        
        with open(self.events_file) as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    event = FileEvent(**data)
                    
                    # 过滤条件
                    if start_time and event.timestamp < start_time:
                        continue
                    if end_time and event.timestamp > end_time:
                        continue
                    if event_type and event.event_type != event_type:
                        continue
                    if path_prefix and not event.path.startswith(path_prefix):
                        continue
                    if package and event.package != package:
                        continue
                    if risk_level and event.risk_level != risk_level:
                        continue
                    
                    events.append(event)
                    if len(events) >= limit:
                        break
                except json.JSONDecodeError:
                    continue
        
        return events
    
    def get_new_items(self, since: Optional[str] = None) -> Dict[str, List[FileEvent]]:
        """获取新增项目（按类型分组）"""
        events = self.get_events(event_type="created", start_time=since)
        
        result = {
            "packages": [],
            "files": [],
            "directories": [],
            "docker": [],
        }
        
        for event in events:
            if event.package:
                result["packages"].append(event)
            elif "/var/lib/docker/containers/" in event.path:
                result["docker"].append(event)
            elif event.is_directory:
                result["directories"].append(event)
            else:
                result["files"].append(event)
        
        return result
    
    def _check_rotation(self):
        """检查日志轮转"""
        if self.events_file.exists():
            size = self.events_file.stat().st_size
            if size > self.config.max_events * 200:  # 估算大小
                self._rotate()
    
    def _rotate(self):
        """轮转事件日志"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = self.events_file.with_suffix(f".jsonl.{timestamp}")
        shutil.move(self.events_file, backup)
        self.logger.info(f"事件日志已轮转: {backup}")
    
    def cleanup_old_events(self, days: int = None):
        """清理旧事件"""
        days = days or self.config.retention_days
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
        
        if not self.events_file.exists():
            return
        
        temp_file = self.events_file.with_suffix(".temp")
        kept = 0
        
        with open(self.events_file) as f_in, open(temp_file, 'w') as f_out:
            for line in f_in:
                try:
                    data = json.loads(line.strip())
                    if data.get("timestamp", "") >= cutoff_str:
                        f_out.write(line)
                        kept += 1
                except json.JSONDecodeError:
                    continue
        
        shutil.move(temp_file, self.events_file)
        self.logger.info(f"清理完成，保留 {kept} 条事件")


class StateManager:
    """系统状态管理器"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.state_dir = Path(STATE_DIR)
        self.state_dir.mkdir(parents=True, exist_ok=True)
    
    def capture_state(self, name: Optional[str] = None) -> SystemState:
        """捕获当前系统状态"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        version = name or timestamp
        
        self.logger.info(f"开始捕获系统状态: {version}")
        
        state = SystemState(
            timestamp=timestamp,
            config_version=version,
        )
        
        # 捕获文件状态
        state.files = self._capture_file_state()
        
        # 捕获已安装包列表
        state.packages = self._get_installed_packages()
        
        # 捕获 sysctl 参数
        state.sysctl = self._get_sysctl_params()
        
        # 捕获服务状态
        state.services = self._get_service_status()
        
        # 保存状态
        self._save_state(state)
        
        self.logger.info(f"状态捕获完成: {len(state.files)} 文件, {len(state.packages)} 包")
        
        return state
    
    def _capture_file_state(self) -> Dict[str, Dict]:
        """捕获文件状态"""
        files = {}
        ignore_patterns = self.config.ignore_patterns
        
        # 如果监控用户目录，添加用户配置路径
        monitor_paths = ["/usr", "/var", "/opt", "/etc"]
        if self.config.monitor_user_dirs:
            monitor_paths.extend(USER_CONFIG_DIRS)
        
        for base_path in monitor_paths:
            base = Path(base_path)
            if not base.exists():
                continue
            
            try:
                for item in base.rglob("*"):
                    # 检查是否在忽略列表
                    path_str = str(item)
                    if any(path_str.startswith(p) for p in ignore_patterns):
                        continue
                    
                    if item.is_file():
                        try:
                            stat = item.stat()
                            files[path_str] = {
                                "size": stat.st_size,
                                "mtime": stat.st_mtime,
                                "checksum": self._quick_checksum(item) if stat.st_size < 10 * 1024 * 1024 else None,
                            }
                        except (PermissionError, OSError):
                            continue
            except PermissionError:
                continue
        
        return files
    
    def _quick_checksum(self, file_path: Path) -> str:
        """快速计算文件 MD5"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()[:16]
        except (PermissionError, OSError):
            return ""
    
    def _get_installed_packages(self) -> List[str]:
        """获取已安装软件包列表"""
        packages = []
        
        # Debian/Ubuntu
        if Path("/etc/debian_version").exists():
            try:
                result = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Package}\\n"],
                    capture_output=True, text=True
                )
                packages = result.stdout.strip().split('\n')
            except subprocess.SubprocessError:
                pass
        
        # RedHat/CentOS
        elif Path("/etc/redhat-release").exists():
            try:
                result = subprocess.run(
                    ["rpm", "-qa", "--queryformat=%{NAME}\\n"],
                    capture_output=True, text=True
                )
                packages = result.stdout.strip().split('\n')
            except subprocess.SubprocessError:
                pass
        
        return sorted(packages)
    
    def _get_sysctl_params(self) -> Dict[str, str]:
        """获取 sysctl 参数"""
        params = {}
        try:
            result = subprocess.run(
                ["sysctl", "-a"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    params[key.strip()] = value.strip()
        except subprocess.SubprocessError:
            pass
        return params
    
    def _get_service_status(self) -> Dict[str, str]:
        """获取服务状态"""
        services = {}
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-pager"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if '.service' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[0]
                        status = parts[3] if len(parts) > 3 else parts[2]
                        services[name] = status
        except subprocess.SubprocessError:
            pass
        return services
    
    def _save_state(self, state: SystemState):
        """保存状态到文件"""
        filename = f"state_{state.config_version.replace(':', '').replace(' ', '_')}.json"
        state_file = self.state_dir / filename
        
        with open(state_file, 'w') as f:
            json.dump(asdict(state), f, indent=2)
        
        self.logger.info(f"状态已保存: {state_file}")
    
    def load_state(self, name: str) -> Optional[SystemState]:
        """加载指定状态"""
        filename = f"state_{name.replace(':', '').replace(' ', '_')}.json"
        state_file = self.state_dir / filename
        
        if not state_file.exists():
            # 尝试查找最接近的
            states = list(self.state_dir.glob("state_*.json"))
            if states:
                # 按时间排序，找最近的
                states.sort(key=lambda x: x.stat().st_mtime)
                state_file = states[-1]
            else:
                return None
        
        with open(state_file) as f:
            data = json.load(f)
            return SystemState(**data)
    
    def compare_states(self, state1: SystemState, state2: SystemState) -> Dict:
        """比较两个状态"""
        diff = {
            "added_files": [],
            "removed_files": [],
            "modified_files": [],
            "added_packages": [],
            "removed_packages": [],
            "sysctl_changes": {},
            "service_changes": {},
        }
        
        # 文件差异
        files1 = set(state1.files.keys())
        files2 = set(state2.files.keys())
        
        diff["added_files"] = sorted(files2 - files1)
        diff["removed_files"] = sorted(files1 - files2)
        
        for path in files1 & files2:
            if state1.files[path] != state2.files[path]:
                diff["modified_files"].append({
                    "path": path,
                    "old": state1.files[path],
                    "new": state2.files[path],
                })
        
        # 包差异
        packages1 = set(state1.packages)
        packages2 = set(state2.packages)
        
        diff["added_packages"] = sorted(packages2 - packages1)
        diff["removed_packages"] = sorted(packages1 - packages2)
        
        # sysctl 差异
        for key in set(state1.sysctl.keys()) | set(state2.sysctl.keys()):
            old = state1.sysctl.get(key)
            new = state2.sysctl.get(key)
            if old != new:
                diff["sysctl_changes"][key] = {"old": old, "new": new}
        
        # 服务差异
        for name in set(state1.services.keys()) | set(state2.services.keys()):
            old = state1.services.get(name)
            new = state2.services.get(name)
            if old != new:
                diff["service_changes"][name] = {"old": old, "new": new}
        
        return diff
    
    def list_states(self) -> List[str]:
        """列出所有保存的状态"""
        states = []
        for f in self.state_dir.glob("state_*.json"):
            name = f.stem.replace("state_", "")
            states.append(name)
        return sorted(states)
    
    def delete_state(self, name: str):
        """删除指定状态"""
        filename = f"state_{name.replace(':', '').replace(' ', '_')}.json"
        state_file = self.state_dir / filename
        if state_file.exists():
            state_file.unlink()
            self.logger.info(f"状态已删除: {name}")


class PackageTracker:
    """软件包追踪器"""
    
    def __init__(self, config: Config, logger: Logger, event_store: EventStore):
        self.config = config
        self.logger = logger
        self.event_store = event_store
        self.packages_file = Path(config.packages_file)
        self.packages_file.parent.mkdir(parents=True, exist_ok=True)
        self._packages: Dict[str, PackageRecord] = {}
        self._load_packages()
    
    def _load_packages(self):
        """加载已记录的包"""
        if self.packages_file.exists():
            with open(self.packages_file) as f:
                data = json.load(f)
                for name, pkg_data in data.items():
                    self._packages[name] = PackageRecord(**pkg_data)
    
    def _save_packages(self):
        """保存包记录"""
        with open(self.packages_file, 'w') as f:
            json.dump({name: asdict(pkg) for name, pkg in self._packages.items()}, f, indent=2)
    
    def track_installation(self, package_name: str):
        """追踪新安装的包"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 获取包信息
        files = self._get_package_files(package_name)
        config_files = self._get_package_config_files(package_name)
        services = self._get_package_services(package_name)
        dependencies = self._get_package_dependencies(package_name)
        
        record = PackageRecord(
            name=package_name,
            install_time=timestamp,
            files=files,
            config_files=config_files,
            services=services,
            dependencies=dependencies,
        )
        
        self._packages[package_name] = record
        self._save_packages()
        
        self.logger.info(f"追踪包安装: {package_name} ({len(files)} 文件)")
        
        # 关联文件事件
        for file_path in files:
            event = FileEvent(
                timestamp=timestamp,
                event_type="created",
                path=file_path,
                is_directory=False,
                package=package_name,
                risk_level=self._assess_risk(file_path),
            )
            self.event_store.add_event(event)
    
    def _get_package_files(self, package_name: str) -> List[str]:
        """获取包安装的所有文件"""
        files = []
        
        if Path("/etc/debian_version").exists():
            try:
                result = subprocess.run(
                    ["dpkg", "-L", package_name],
                    capture_output=True, text=True
                )
                files = [f for f in result.stdout.strip().split('\n') if f]
            except subprocess.SubprocessError:
                pass
        
        elif Path("/etc/redhat-release").exists():
            try:
                result = subprocess.run(
                    ["rpm", "-ql", package_name],
                    capture_output=True, text=True
                )
                files = [f for f in result.stdout.strip().split('\n') if f]
            except subprocess.SubprocessError:
                pass
        
        return files
    
    def _get_package_config_files(self, package_name: str) -> List[str]:
        """获取包的配置文件"""
        configs = []
        
        if Path("/etc/debian_version").exists():
            try:
                result = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Conffiles}", package_name],
                    capture_output=True, text=True
                )
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if parts:
                            configs.append(parts[0])
            except subprocess.SubprocessError:
                pass
        
        return configs
    
    def _get_package_services(self, package_name: str) -> List[str]:
        """获取包关联的服务"""
        services = []
        try:
            result = subprocess.run(
                ["systemctl", "list-unit-files", "--no-pager"],
                capture_output=True, text=True
            )
            for line in result.stdout.split('\n'):
                if package_name in line.lower() and '.service' in line:
                    parts = line.split()
                    if parts:
                        services.append(parts[0])
        except subprocess.SubprocessError:
            pass
        return services
    
    def _get_package_dependencies(self, package_name: str) -> List[str]:
        """获取包的依赖"""
        deps = []
        
        if Path("/etc/debian_version").exists():
            try:
                result = subprocess.run(
                    ["apt-cache", "depends", package_name],
                    capture_output=True, text=True
                )
                for line in result.stdout.split('\n'):
                    if "Depends:" in line:
                        dep = line.split("Depends:")[-1].strip()
                        deps.append(dep)
            except subprocess.SubprocessError:
                pass
        
        return deps
    
    def _assess_risk(self, path: str) -> str:
        """评估文件风险等级"""
        for sensitive in SECURITY_SENSITIVE_PATHS:
            if path.startswith(sensitive):
                return "high"
        
        if path.startswith("/etc/"):
            return "medium"
        
        if path.startswith("/usr/bin/") or path.startswith("/usr/sbin/"):
            return "medium"
        
        return "low"
    
    def remove_package(self, package_name: str, purge: bool = True) -> bool:
        """彻底移除包"""
        if package_name not in self._packages:
            self.logger.warning(f"包 {package_name} 未被追踪")
            return False
        
        record = self._packages[package_name]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 停止相关服务
        for service in record.services:
            try:
                subprocess.run(["systemctl", "stop", service], capture_output=True)
                subprocess.run(["systemctl", "disable", service], capture_output=True)
                self.logger.info(f"已停止服务: {service}")
            except subprocess.SubprocessError:
                pass
        
        # 使用 apt-get purge 或 yum remove
        if Path("/etc/debian_version").exists():
            cmd = ["apt-get", "purge", "-y", package_name]
        else:
            cmd = ["yum", "remove", "-y", package_name]
        
        try:
            subprocess.run(cmd, capture_output=True)
            self.logger.info(f"已卸载包: {package_name}")
        except subprocess.SubprocessError as e:
            self.logger.error(f"卸载失败: {e}")
            return False
        
        # 清理残留配置文件
        for config_file in record.config_files:
            if Path(config_file).exists():
                try:
                    Path(config_file).unlink()
                    self.logger.info(f"已删除配置: {config_file}")
                except OSError:
                    pass
        
        # 清理用户配置（可选）
        user_configs = [
            Path.home() / ".config" / package_name,
            Path.home() / ".local" / "share" / package_name,
            Path.home() / f".{package_name}",
        ]
        
        for uc in user_configs:
            if uc.exists():
                try:
                    if uc.is_dir():
                        shutil.rmtree(uc)
                    else:
                        uc.unlink()
                    self.logger.info(f"已删除用户配置: {uc}")
                except OSError:
                    pass
        
        # 清理依赖
        if Path("/etc/debian_version").exists():
            subprocess.run(["apt-get", "autoremove", "-y"], capture_output=True)
        
        # 更新记录
        record.removed = True
        record.remove_time = timestamp
        self._save_packages()
        
        return True
    
    def get_tracked_packages(self) -> Dict[str, PackageRecord]:
        """获取所有追踪的包"""
        return self._packages.copy()
    
    def get_active_packages(self) -> List[PackageRecord]:
        """获取未移除的包"""
        return [pkg for pkg in self._packages.values() if not pkg.removed]


class SecurityMonitor:
    """安全监控器"""
    
    def __init__(self, config: Config, logger: Logger, event_store: EventStore):
        self.config = config
        self.logger = logger
        self.event_store = event_store
        self._alerts: List[Dict] = []
    
    def assess_event(self, event: FileEvent) -> str:
        """评估事件风险"""
        path = event.path
        
        # 关键安全文件
        critical_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/pam.d/",
        ]
        
        for cf in critical_files:
            if path.startswith(cf) or path == cf:
                return "critical"
        
        # 系统目录
        if path.startswith("/etc/"):
            return "high"
        
        if path.startswith("/usr/bin/") or path.startswith("/usr/sbin/"):
            return "high"
        
        if path.startswith("/bin/") or path.startswith("/sbin/"):
            return "high"
        
        # 服务相关
        if "/systemd/system/" in path or "/init.d/" in path:
            return "high"
        
        # Docker
        if "/var/lib/docker/" in path:
            return "medium"
        
        # 用户配置
        if "/home/" in path and "/.ssh/" in path:
            return "high"
        
        return "low"
    
    def check_event(self, event: FileEvent) -> Optional[Dict]:
        """检查事件是否需要告警"""
        if not self.config.alert_on_sensitive_changes:
            return None
        
        risk = self.assess_event(event)
        event.risk_level = risk
        
        if risk in ("high", "critical"):
            alert = {
                "timestamp": event.timestamp,
                "path": event.path,
                "event_type": event.event_type,
                "risk_level": risk,
                "message": self._generate_alert_message(event, risk),
            }
            self._alerts.append(alert)
            return alert
        
        return None
    
    def _generate_alert_message(self, event: FileEvent, risk: str) -> str:
        """生成告警消息"""
        risk_desc = {
            "critical": "关键安全文件",
            "high": "重要系统文件",
            "medium": "可能影响系统",
        }
        
        desc = risk_desc.get(risk, "普通文件")
        
        if event.event_type == "modified":
            return f"⚠️ {desc}被修改: {event.path}"
        elif event.event_type == "created":
            return f"⚠️ {desc}被创建: {event.path}"
        elif event.event_type == "deleted":
            return f"⚠️ {desc}被删除: {event.path}"
        else:
            return f"⚠️ {desc}发生变化: {event.path}"
    
    def get_alerts(self, since: Optional[str] = None) -> List[Dict]:
        """获取告警列表"""
        if since:
            return [a for a in self._alerts if a["timestamp"] >= since]
        return self._alerts.copy()
    
    def clear_alerts(self):
        """清除告警"""
        self._alerts.clear()


class ConfigManager:
    """系统配置管理器"""
    
    def __init__(self, config: Config, logger: Logger, state_manager: StateManager):
        self.config = config
        self.logger = logger
        self.state_manager = state_manager
        self.config_backup_dir = BASE_DIR / "config_backups"
        self.config_backup_dir.mkdir(parents=True, exist_ok=True)
    
    def save_sysctl(self, name: Optional[str] = None) -> str:
        """保存 sysctl 配置"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = name or f"sysctl_{timestamp}"
        backup_file = self.config_backup_dir / f"{backup_name}.conf"
        
        # 获取当前 sysctl 参数
        params = self.state_manager._get_sysctl_params()
        
        with open(backup_file, 'w') as f:
            f.write(f"# sysctl 配置备份 - {timestamp}\n")
            f.write(f"# 由 file_monitor 生成\n\n")
            for key, value in sorted(params.items()):
                f.write(f"{key} = {value}\n")
        
        self.logger.info(f"sysctl 配置已保存: {backup_file}")
        return str(backup_file)
    
    def restore_sysctl(self, name: str) -> bool:
        """恢复 sysctl 配置"""
        backup_file = self.config_backup_dir / f"{name}.conf"
        
        if not backup_file.exists():
            self.logger.error(f"配置备份不存在: {name}")
            return False
        
        try:
            subprocess.run(
                ["sysctl", "-p", str(backup_file)],
                capture_output=True
            )
            self.logger.info(f"sysctl 配置已恢复: {name}")
            return True
        except subprocess.SubprocessError as e:
            self.logger.error(f"恢复失败: {e}")
            return False
    
    def save_etc_configs(self, name: Optional[str] = None) -> str:
        """保存 /etc 配置文件"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = name or f"etc_{timestamp}"
        backup_dir = self.config_backup_dir / backup_name
        
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        etc_path = Path("/etc")
        important_configs = [
            "passwd", "shadow", "group", "sudoers",
            "fstab", "hosts", "hostname", "crontab",
            "ssh/sshd_config", "ssh/sshd_config.d",
            "systemd/system", "nginx", "apache2",
            "mysql", "postgresql", "redis",
        ]
        
        for config_name in important_configs:
            src = etc_path / config_name
            if src.exists():
                dst = backup_dir / config_name
                try:
                    if src.is_dir():
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
                except (PermissionError, OSError) as e:
                    self.logger.warning(f"无法复制 {config_name}: {e}")
        
        self.logger.info(f"/etc 配置已保存: {backup_dir}")
        return str(backup_dir)
    
    def restore_etc_configs(self, name: str) -> bool:
        """恢复 /etc 配置"""
        backup_dir = self.config_backup_dir / name
        
        if not backup_dir.exists():
            self.logger.error(f"配置备份不存在: {name}")
            return False
        
        try:
            for item in backup_dir.iterdir():
                dst = Path("/etc") / item.name
                if dst.exists():
                    if dst.is_dir():
                        shutil.rmtree(dst)
                    else:
                        dst.unlink()
                
                if item.is_dir():
                    shutil.copytree(item, dst)
                else:
                    shutil.copy2(item, dst)
            
            self.logger.info(f"/etc 配置已恢复: {name}")
            return True
        except (PermissionError, OSError) as e:
            self.logger.error(f"恢复失败: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """列出所有配置备份"""
        backups = []
        
        for item in self.config_backup_dir.iterdir():
            if item.is_file() and item.suffix == ".conf":
                backups.append({
                    "name": item.stem,
                    "type": "sysctl",
                    "path": str(item),
                    "time": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
            elif item.is_dir():
                backups.append({
                    "name": item.name,
                    "type": "etc",
                    "path": str(item),
                    "time": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
        
        return sorted(backups, key=lambda x: x["time"], reverse=True)
    
    def delete_backup(self, name: str):
        """删除配置备份"""
        backup_file = self.config_backup_dir / f"{name}.conf"
        backup_dir = self.config_backup_dir / name
        
        if backup_file.exists():
            backup_file.unlink()
            self.logger.info(f"sysctl 备份已删除: {name}")
        
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
            self.logger.info(f"etc 备份已删除: {name}")


class WhitelistManager:
    """白名单管理器"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.whitelist_file = Path(config.whitelist_file)
        self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        self._whitelist: Dict[str, Dict] = {}
        self._load()
    
    def _load(self):
        """加载白名单"""
        if self.whitelist_file.exists():
            with open(self.whitelist_file) as f:
                self._whitelist = json.load(f)
    
    def _save(self):
        """保存白名单"""
        with open(self.whitelist_file, 'w') as f:
            json.dump(self._whitelist, f, indent=2)
    
    def add(self, path: str, reason: str = ""):
        """添加到白名单"""
        self._whitelist[path] = {
            "added_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "reason": reason,
        }
        self._save()
        self.logger.info(f"已添加白名单: {path}")
    
    def remove(self, path: str):
        """从白名单移除"""
        if path in self._whitelist:
            del self._whitelist[path]
            self._save()
            self.logger.info(f"已移除白名单: {path}")
    
    def is_whitelisted(self, path: str) -> bool:
        """检查是否在白名单"""
        return path in self._whitelist
    
    def get_all(self) -> Dict[str, Dict]:
        """获取所有白名单项"""
        return self._whitelist.copy()
    
    def clear(self):
        """清空白名单"""
        self._whitelist.clear()
        self._save()


class FileMonitorHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """文件系统事件处理器"""
    
    def __init__(self, config: Config, logger: Logger, event_store: EventStore, 
                 security_monitor: SecurityMonitor, whitelist: WhitelistManager,
                 package_tracker: PackageTracker):
        self.config = config
        self.logger = logger
        self.event_store = event_store
        self.security_monitor = security_monitor
        self.whitelist = whitelist
        self.package_tracker = package_tracker
    
    def _should_ignore(self, path: str) -> bool:
        """检查是否应该忽略"""
        # 检查白名单
        if self.whitelist.is_whitelisted(path):
            return True
        
        # 检查忽略模式
        for pattern in self.config.ignore_patterns:
            if path.startswith(pattern):
                return True
        
        return False
    
    def _create_event(self, event_type: str, path: str, is_directory: bool) -> FileEvent:
        """创建事件记录"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 获取文件信息
        size = None
        checksum = None
        
        if not is_directory and Path(path).exists():
            try:
                stat = Path(path).stat()
                size = stat.st_size
                if size < 10 * 1024 * 1024:  # 小于 10MB 计算 checksum
                    with open(path, 'rb') as f:
                        checksum = hashlib.md5(f.read()).hexdigest()[:16]
            except (PermissionError, OSError):
                pass
        
        # 尝试获取所属包
        package = self._get_package_for_path(path)
        
        event = FileEvent(
            timestamp=timestamp,
            event_type=event_type,
            path=path,
            is_directory=is_directory,
            size=size,
            checksum=checksum,
            package=package,
        )
        
        # 安全评估
        self.security_monitor.check_event(event)
        
        return event
    
    def _get_package_for_path(self, path: str) -> Optional[str]:
        """获取文件所属的包"""
        if Path("/etc/debian_version").exists():
            try:
                result = subprocess.run(
                    ["dpkg", "-S", path],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    return result.stdout.split(':')[0].strip()
            except subprocess.SubprocessError:
                pass
        
        elif Path("/etc/redhat-release").exists():
            try:
                result = subprocess.run(
                    ["rpm", "-qf", path],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except subprocess.SubprocessError:
                pass
        
        return None
    
    def on_created(self, event):
        """文件/目录创建事件"""
        if WATCHDOG_AVAILABLE:
            path = event.src_path
            is_dir = event.is_directory
            
            if self._should_ignore(path):
                return
            
            file_event = self._create_event("created", path, is_dir)
            self.event_store.add_event(file_event)
            self.logger.debug(f"创建: {path}")
            
            # 高风险告警
            if file_event.risk_level in ("high", "critical"):
                self.logger.warning(f"⚠️ 安全告警: {file_event.path}")
    
    def on_deleted(self, event):
        """文件/目录删除事件"""
        if WATCHDOG_AVAILABLE:
            path = event.src_path
            is_dir = event.is_directory
            
            if self._should_ignore(path):
                return
            
            file_event = self._create_event("deleted", path, is_dir)
            self.event_store.add_event(file_event)
            self.logger.debug(f"删除: {path}")
            
            if file_event.risk_level in ("high", "critical"):
                self.logger.warning(f"⚠️ 安全告警: {file_event.path}")
    
    def on_modified(self, event):
        """文件/目录修改事件"""
        if WATCHDOG_AVAILABLE:
            path = event.src_path
            is_dir = event.is_directory
            
            if self._should_ignore(path):
                return
            
            file_event = self._create_event("modified", path, is_dir)
            self.event_store.add_event(file_event)
            self.logger.debug(f"修改: {path}")
            
            if file_event.risk_level in ("high", "critical"):
                self.logger.warning(f"⚠️ 安全告警: {file_event.path}")
    
    def on_moved(self, event):
        """文件/目录移动事件"""
        if WATCHDOG_AVAILABLE:
            src_path = event.src_path
            dest_path = event.dest_path
            is_dir = event.is_directory
            
            if self._should_ignore(src_path) and self._should_ignore(dest_path):
                return
            
            # 记录源路径删除
            if not self._should_ignore(src_path):
                file_event = self._create_event("moved_from", src_path, is_dir)
                self.event_store.add_event(file_event)
            
            # 记录目标路径创建
            if not self._should_ignore(dest_path):
                file_event = self._create_event("moved_to", dest_path, is_dir)
                self.event_store.add_event(file_event)
            
            self.logger.debug(f"移动: {src_path} -> {dest_path}")


class MonitorService:
    """监控服务"""
    
    def __init__(self):
        self.config = Config.load()
        self.logger = Logger(self.config)
        self.event_store = EventStore(self.config, self.logger)
        self.state_manager = StateManager(self.config, self.logger)
        self.whitelist = WhitelistManager(self.config, self.logger)
        self.package_tracker = PackageTracker(self.config, self.logger, self.event_store)
        self.security_monitor = SecurityMonitor(self.config, self.logger, self.event_store)
        self.config_manager = ConfigManager(self.config, self.logger, self.state_manager)
        
        self._observer = None
        self._running = False
        self._stop_event = Event()
    
    def start(self):
        """启动监控"""
        if not WATCHDOG_AVAILABLE:
            self.logger.error("watchdog 未安装，无法启动监控")
            return False
        
        self.logger.info("启动文件系统监控...")
        
        # 创建事件处理器
        handler = FileMonitorHandler(
            self.config, self.logger, self.event_store,
            self.security_monitor, self.whitelist, self.package_tracker
        )
        
        # 创建观察者
        self._observer = Observer()
        
        # 监控路径
        monitor_paths = ["/usr", "/var", "/opt", "/etc"]
        if self.config.monitor_user_dirs:
            monitor_paths.extend(USER_CONFIG_DIRS)
        
        for path in monitor_paths:
            if Path(path).exists():
                try:
                    self._observer.schedule(handler, path, recursive=True)
                    self.logger.info(f"监控路径: {path}")
                except Exception as e:
                    self.logger.warning(f"无法监控 {path}: {e}")
        
        self._observer.start()
        self._running = True
        
        # 写入 PID 文件
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))
        
        self.logger.info(f"监控已启动，PID: {os.getpid()}")
        
        return True
    
    def stop(self):
        """停止监控"""
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join()
            self._running = False
            
            if PID_FILE.exists():
                PID_FILE.unlink()
            
            self.logger.info("监控已停止")
    
    def is_running(self) -> bool:
        """检查是否运行"""
        return self._running and (self._observer is not None and self._observer.is_alive())
    
    def wait(self):
        """等待监控"""
        try:
            while self._running:
                self._stop_event.wait(1)
        except KeyboardInterrupt:
            self.stop()


class CLI:
    """命令行界面"""
    
    def __init__(self):
        self.service = MonitorService()
    
    def run(self):
        """运行 CLI"""
        parser = argparse.ArgumentParser(
            description="文件系统监控与清理工具",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
示例:
  %(prog)s start              # 启动监控守护进程
  %(prog)s stop               # 停止监控
  %(prog)s status             # 查看状态
  %(prog)s capture            # 捕获当前系统状态
  %(prog)s diff <state1> <state2>  # 比较两个状态
  %(prog)s clean              # 清理新增项目
  %(prog)s packages           # 查看追踪的软件包
  %(prog)s remove <package>   # 彻底移除软件包
  %(prog)s alerts             # 查看安全告警
  %(prog)s config save        # 保存系统配置
  %(prog)s config restore <name>  # 恢复配置
  %(prog)s whitelist          # 白名单管理
            """
        )
        
        subparsers = parser.add_subparsers(dest="command", help="命令")
        
        # start 命令
        subparsers.add_parser("start", help="启动监控守护进程")
        
        # stop 命令
        subparsers.add_parser("stop", help="停止监控")
        
        # status 命令
        subparsers.add_parser("status", help="查看状态")
        
        # capture 命令
        capture_parser = subparsers.add_parser("capture", help="捕获系统状态")
        capture_parser.add_argument("-n", "--name", help="状态名称")
        
        # diff 命令
        diff_parser = subparsers.add_parser("diff", help="比较两个状态")
        diff_parser.add_argument("state1", help="状态1名称")
        diff_parser.add_argument("state2", help="状态2名称")
        
        # clean 命令
        subparsers.add_parser("clean", help="清理新增项目")
        
        # packages 命令
        subparsers.add_parser("packages", help="查看追踪的软件包")
        
        # remove 命令
        remove_parser = subparsers.add_parser("remove", help="彻底移除软件包")
        remove_parser.add_argument("package", help="软件包名称")
        remove_parser.add_argument("--no-purge", action="store_true", help="不清理配置文件")
        
        # alerts 命令
        subparsers.add_parser("alerts", help="查看安全告警")
        
        # events 命令
        events_parser = subparsers.add_parser("events", help="查看事件")
        events_parser.add_argument("-t", "--type", help="事件类型")
        events_parser.add_argument("-p", "--path", help="路径前缀")
        events_parser.add_argument("-l", "--limit", type=int, default=100, help="数量限制")
        
        # config 命令
        config_parser = subparsers.add_parser("config", help="系统配置管理")
        config_parser.add_argument("action", choices=["save", "restore", "list", "delete"])
        config_parser.add_argument("-n", "--name", help="配置名称")
        config_parser.add_argument("-t", "--type", choices=["sysctl", "etc", "all"], default="all")
        
        # whitelist 命令
        whitelist_parser = subparsers.add_parser("whitelist", help="白名单管理")
        whitelist_parser.add_argument("action", choices=["list", "add", "remove", "clear"])
        whitelist_parser.add_argument("-p", "--path", help="路径")
        whitelist_parser.add_argument("-r", "--reason", help="添加原因")
        
        # states 命令
        subparsers.add_parser("states", help="列出所有保存的状态")
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        # 执行命令
        self._execute_command(args)
    
    def _execute_command(self, args):
        """执行命令"""
        command = args.command
        
        try:
            if command == "start":
                self._cmd_start()
            elif command == "stop":
                self._cmd_stop()
            elif command == "status":
                self._cmd_status()
            elif command == "capture":
                self._cmd_capture(args.name)
            elif command == "diff":
                self._cmd_diff(args.state1, args.state2)
            elif command == "clean":
                self._cmd_clean()
            elif command == "packages":
                self._cmd_packages()
            elif command == "remove":
                self._cmd_remove(args.package, not args.no_purge)
            elif command == "alerts":
                self._cmd_alerts()
            elif command == "events":
                self._cmd_events(args.type, args.path, args.limit)
            elif command == "config":
                self._cmd_config(args.action, args.name, args.type)
            elif command == "whitelist":
                self._cmd_whitelist(args.action, args.path, args.reason)
            elif command == "states":
                self._cmd_states()
            else:
                print(f"未知命令: {command}")
        except Exception as e:
            print(f"错误: {e}")
    
    def _cmd_start(self):
        """启动监控"""
        if self.service.is_running():
            print("监控已在运行")
            return
        
        if self.service.start():
            print("监控已启动")
            print(f"PID: {os.getpid()}")
            print("日志: " + str(self.service.config.log_file))
        else:
            print("启动失败")
    
    def _cmd_stop(self):
        """停止监控"""
        self.service.stop()
        print("监控已停止")
    
    def _cmd_status(self):
        """查看状态"""
        print("=== 监控状态 ===")
        print(f"运行状态: {'运行中' if self.service.is_running() else '已停止'}")
        
        if PID_FILE.exists():
            print(f"PID 文件: {PID_FILE}")
        
        print(f"\n=== 统计信息 ===")
        
        # 事件统计
        events = self.service.event_store.get_events(limit=10000)
        print(f"总事件数: {len(events)}")
        
        # 按类型统计
        by_type = defaultdict(int)
        for e in events:
            by_type[e.event_type] += 1
        print(f"按类型: {dict(by_type)}")
        
        # 告警统计
        alerts = self.service.security_monitor.get_alerts()
        print(f"安全告警: {len(alerts)}")
        
        # 包统计
        packages = self.service.package_tracker.get_active_packages()
        print(f"追踪的包: {len(packages)}")
    
    def _cmd_capture(self, name: Optional[str]):
        """捕获状态"""
        print("正在捕获系统状态...")
        state = self.service.state_manager.capture_state(name)
        print(f"状态已保存: {state.config_version}")
        print(f"文件数: {len(state.files)}")
        print(f"软件包: {len(state.packages)}")
    
    def _cmd_diff(self, state1: str, state2: str):
        """比较状态"""
        s1 = self.service.state_manager.load_state(state1)
        s2 = self.service.state_manager.load_state(state2)
        
        if not s1:
            print(f"状态不存在: {state1}")
            return
        if not s2:
            print(f"状态不存在: {state2}")
            return
        
        diff = self.service.state_manager.compare_states(s1, s2)
        
        print(f"=== 状态比较: {state1} vs {state2} ===")
        print(f"\n新增文件: {len(diff['added_files'])}")
        if diff['added_files'][:10]:
            for f in diff['added_files'][:10]:
                print(f"  + {f}")
        
        print(f"\n删除文件: {len(diff['removed_files'])}")
        if diff['removed_files'][:10]:
            for f in diff['removed_files'][:10]:
                print(f"  - {f}")
        
        print(f"\n修改文件: {len(diff['modified_files'])}")
        
        print(f"\n新增包: {diff['added_packages']}")
        print(f"删除包: {diff['removed_packages']}")
        
        print(f"\nsysctl 变更: {len(diff['sysctl_changes'])}")
        print(f"服务变更: {len(diff['service_changes'])}")
    
    def _cmd_clean(self):
        """清理新增项目"""
        print("=== 新增项目 ===")
        new_items = self.service.event_store.get_new_items()
        
        print(f"\n新增文件: {len(new_items['files'])}")
        print(f"新增目录: {len(new_items['directories'])}")
        print(f"Docker 容器: {len(new_items['docker'])}")
        print(f"软件包: {len(new_items['packages'])}")
        
        # 显示包详情
        packages = self.service.package_tracker.get_active_packages()
        if packages:
            print("\n=== 追踪的软件包 ===")
            for pkg in packages:
                print(f"  {pkg.name}")
                print(f"    安装时间: {pkg.install_time}")
                print(f"    文件数: {len(pkg.files)}")
                print(f"    服务: {pkg.services}")
    
    def _cmd_packages(self):
        """查看追踪的包"""
        packages = self.service.package_tracker.get_tracked_packages()
        
        print("=== 软件包追踪 ===")
        for name, pkg in packages.items():
            status = "已移除" if pkg.removed else "活跃"
            print(f"\n{name} [{status}]")
            print(f"  安装时间: {pkg.install_time}")
            if pkg.removed:
                print(f"  移除时间: {pkg.remove_time}")
            print(f"  文件数: {len(pkg.files)}")
            print(f"  配置文件: {len(pkg.config_files)}")
            print(f"  服务: {pkg.services}")
    
    def _cmd_remove(self, package: str, purge: bool):
        """移除软件包"""
        print(f"正在移除软件包: {package}")
        
        if self.service.package_tracker.remove_package(package, purge):
            print(f"✓ 软件包 {package} 已彻底移除")
        else:
            print(f"✗ 移除失败")
    
    def _cmd_alerts(self):
        """查看告警"""
        alerts = self.service.security_monitor.get_alerts()
        
        print("=== 安全告警 ===")
        if not alerts:
            print("无告警")
            return
        
        for alert in alerts[-20:]:  # 最近 20 条
            print(f"\n[{alert['risk_level']}] {alert['timestamp']}")
            print(f"  {alert['message']}")
    
    def _cmd_events(self, event_type: Optional[str], path: Optional[str], limit: int):
        """查看事件"""
        events = self.service.event_store.get_events(
            event_type=event_type,
            path_prefix=path,
            limit=limit
        )
        
        print(f"=== 事件列表 (共 {len(events)} 条) ===")
        for event in events:
            print(f"\n[{event.event_type}] {event.timestamp}")
            print(f"  路径: {event.path}")
            print(f"  类型: {'目录' if event.is_directory else '文件'}")
            if event.package:
                print(f"  包: {event.package}")
            if event.risk_level != "low":
                print(f"  风险: {event.risk_level}")
    
    def _cmd_config(self, action: str, name: Optional[str], config_type: str):
        """配置管理"""
        if action == "save":
            if config_type == "sysctl" or config_type == "all":
                file = self.service.config_manager.save_sysctl(name)
                print(f"sysctl 配置已保存: {file}")
            if config_type == "etc" or config_type == "all":
                dir = self.service.config_manager.save_etc_configs(name)
                print(f"/etc 配置已保存: {dir}")
        
        elif action == "restore":
            if not name:
                print("请指定配置名称")
                return
            if config_type == "sysctl" or config_type == "all":
                self.service.config_manager.restore_sysctl(name)
            if config_type == "etc" or config_type == "all":
                self.service.config_manager.restore_etc_configs(name)
        
        elif action == "list":
            backups = self.service.config_manager.list_backups()
            print("=== 配置备份 ===")
            for b in backups:
                print(f"  {b['name']} [{b['type']}] - {b['time']}")
        
        elif action == "delete":
            if not name:
                print("请指定配置名称")
                return
            self.service.config_manager.delete_backup(name)
            print(f"配置备份已删除: {name}")
    
    def _cmd_whitelist(self, action: str, path: Optional[str], reason: Optional[str]):
        """白名单管理"""
        if action == "list":
            whitelist = self.service.whitelist.get_all()
            print("=== 白名单 ===")
            for p, info in whitelist.items():
                print(f"  {p}")
                print(f"    添加时间: {info['added_time']}")
                if info['reason']:
                    print(f"    原因: {info['reason']}")
        
        elif action == "add":
            if not path:
                print("请指定路径")
                return
            self.service.whitelist.add(path, reason or "")
            print(f"已添加白名单: {path}")
        
        elif action == "remove":
            if not path:
                print("请指定路径")
                return
            self.service.whitelist.remove(path)
            print(f"已移除白名单: {path}")
        
        elif action == "clear":
            self.service.whitelist.clear()
            print("白名单已清空")
    
    def _cmd_states(self):
        """列出状态"""
        states = self.service.state_manager.list_states()
        print("=== 保存的状态 ===")
        for s in states:
            print(f"  {s}")


def main():
    """主入口"""
    # 检查 root 权限
    if os.geteuid() != 0:
        print("错误: 此工具需要 root 权限运行")
        print("请使用: sudo python3 file_monitor.py")
        sys.exit(1)
    
    # 检查依赖
    if not WATCHDOG_AVAILABLE:
        print("\n请安装 watchdog:")
        print("  pip install watchdog")
        print("\n或使用系统包管理器:")
        print("  apt install python3-watchdog  # Debian/Ubuntu")
        print("  pip3 install watchdog          # 其他系统")
        sys.exit(1)
    
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()