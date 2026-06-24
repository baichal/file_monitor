#!/usr/bin/env python3
"""
文件系统监控与清理工具 - Python 重构版（完整版）

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
import atexit
import fnmatch
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Callable
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from threading import Thread, Event, Lock

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

BASE_DIR = Path("/var/lib/file_monitor")
CONFIG_FILE = BASE_DIR / "config.json"
STATE_DIR = BASE_DIR / "states"
EVENTS_FILE = BASE_DIR / "events.jsonl"
PACKAGES_FILE = BASE_DIR / "packages.json"
WHITELIST_FILE = BASE_DIR / "whitelist.json"
PID_FILE = BASE_DIR / "monitor.pid"
LOG_FILE = BASE_DIR / "monitor.log"
ALERTS_FILE = BASE_DIR / "alerts.jsonl"
DOCKER_FILE = BASE_DIR / "docker.json"

DEFAULT_IGNORE_PATTERNS = [
    "/proc", "/sys", "/dev", "/run", "/tmp",
    "/var/log", "/var/cache", "/var/lib/file_monitor",
    "/lost+found", "/mnt", "/media",
]

USER_CONFIG_DIRS = ["/home", "/root"]

SECURITY_CRITICAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/pam.d",
]

SECURITY_HIGH_DIRS = [
    "/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/etc/systemd/system", "/etc/init.d",
]


# ==================== 数据模型 ====================

@dataclass
class Config:
    base_dir: str = str(BASE_DIR)
    log_file: str = str(LOG_FILE)
    events_file: str = str(EVENTS_FILE)
    packages_file: str = str(PACKAGES_FILE)
    whitelist_file: str = str(WHITELIST_FILE)
    ignore_patterns: List[str] = field(default_factory=lambda: DEFAULT_IGNORE_PATTERNS.copy())
    monitor_user_dirs: bool = True
    alert_on_sensitive_changes: bool = True
    max_events: int = 100000
    log_rotation_size: int = 10 * 1024 * 1024
    retention_days: int = 30
    monitor_paths: List[str] = field(default_factory=lambda: ["/usr", "/var", "/opt", "/etc"])

    def save(self):
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> 'Config':
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    data = json.load(f)
                    return cls(**data)
            except (json.JSONDecodeError, TypeError):
                pass
        cfg = cls()
        cfg.save()
        return cfg


@dataclass
class FileEvent:
    timestamp: str
    event_type: str
    path: str
    is_directory: bool
    size: Optional[int] = None
    checksum: Optional[str] = None
    package: Optional[str] = None
    risk_level: str = "low"
    notes: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict) -> 'FileEvent':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class PackageRecord:
    name: str
    install_time: str
    files: List[str] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    user_configs: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    removed: bool = False
    remove_time: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DockerContainer:
    container_id: str
    name: str
    image: str
    created: str
    data_paths: List[str] = field(default_factory=list)
    removed: bool = False


@dataclass
class SystemState:
    timestamp: str
    config_version: str = ""
    files: Dict[str, Dict] = field(default_factory=dict)
    packages: List[str] = field(default_factory=list)
    sysctl: Dict[str, str] = field(default_factory=dict)
    services: Dict[str, str] = field(default_factory=dict)
    docker_containers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'SystemState':
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Alert:
    timestamp: str
    path: str
    event_type: str
    risk_level: str
    message: str

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


# ==================== 工具函数 ====================

def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_root() -> bool:
    return os.geteuid() == 0


def check_root():
    if not is_root():
        print("错误: 此工具需要 root 权限运行")
        print("请使用: sudo python3 file_monitor.py")
        sys.exit(1)


def detect_os() -> str:
    if Path("/etc/debian_version").exists():
        return "debian"
    if Path("/etc/redhat-release").exists():
        return "redhat"
    if Path("/etc/arch-release").exists():
        return "arch"
    return "unknown"


def run_cmd(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def md5_file(path: Path, max_size: int = 10 * 1024 * 1024) -> Optional[str]:
    try:
        if path.stat().st_size > max_size:
            return None
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except (PermissionError, OSError):
        return None


# ==================== 日志管理 ====================

class LogManager:
    def __init__(self, config: Config):
        self.config = config
        self._logger: Optional[logging.Logger] = None
        self._setup()

    def _setup(self):
        log_path = Path(self.config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        logger = logging.getLogger("file_monitor")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()

        fh = logging.FileHandler(log_path)
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(fh)

        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(logging.WARNING)
        sh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(sh)

        self._logger = logger

    @property
    def logger(self) -> logging.Logger:
        if self._logger is None:
            self._setup()
        return self._logger

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

    def rotate_if_needed(self):
        log_path = Path(self.config.log_file)
        if log_path.exists() and log_path.stat().st_size > self.config.log_rotation_size:
            try:
                backup = log_path.with_suffix(".log.1")
                if backup.exists():
                    backup.unlink()
                log_path.rename(backup)
                self._setup()
                self.info("日志已轮转")
            except OSError:
                pass


# ==================== 事件存储 ====================

class EventStore:
    def __init__(self, config: Config, log: LogManager):
        self.config = config
        self.log = log
        self.events_file = Path(config.events_file)
        self.events_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def add(self, event: FileEvent):
        with self._lock:
            try:
                with open(self.events_file, 'a') as f:
                    f.write(event.to_json() + '\n')
            except OSError as e:
                self.log.error(f"写入事件失败: {e}")

    def query(self,
              start_time: Optional[str] = None,
              end_time: Optional[str] = None,
              event_type: Optional[str] = None,
              path_prefix: Optional[str] = None,
              package: Optional[str] = None,
              risk_level: Optional[str] = None,
              limit: int = 1000,
              reverse: bool = False) -> List[FileEvent]:
        events = []
        if not self.events_file.exists():
            return events

        lines = []
        with open(self.events_file) as f:
            lines = f.readlines()

        if reverse:
            lines = reversed(lines)

        for line in lines:
            try:
                data = json.loads(line.strip())
                event = FileEvent.from_dict(data)

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

    def stats(self) -> Dict[str, int]:
        stats = defaultdict(int)
        by_type = defaultdict(int)
        by_risk = defaultdict(int)

        if self.events_file.exists():
            with open(self.events_file) as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        stats["total"] += 1
                        by_type[data.get("event_type", "unknown")] += 1
                        by_risk[data.get("risk_level", "low")] += 1
                    except json.JSONDecodeError:
                        continue

        stats["by_type"] = dict(by_type)
        stats["by_risk"] = dict(by_risk)
        return dict(stats)

    def cleanup_old(self, days: int = None):
        days = days or self.config.retention_days
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        if not self.events_file.exists():
            return 0

        temp = self.events_file.with_suffix(".jsonl.tmp")
        kept = 0

        with open(self.events_file) as f_in, open(temp, 'w') as f_out:
            for line in f_in:
                try:
                    data = json.loads(line.strip())
                    if data.get("timestamp", "") >= cutoff_str:
                        f_out.write(line)
                        kept += 1
                except json.JSONDecodeError:
                    continue

        temp.replace(self.events_file)
        self.log.info(f"事件清理完成，保留 {kept} 条")
        return kept

    def clear(self):
        if self.events_file.exists():
            self.events_file.unlink()
        self.log.info("事件已清空")


# ==================== 白名单管理 ====================

class WhitelistManager:
    def __init__(self, config: Config, log: LogManager):
        self.config = config
        self.log = log
        self.whitelist_file = Path(config.whitelist_file)
        self._whitelist: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        if self.whitelist_file.exists():
            try:
                with open(self.whitelist_file) as f:
                    self._whitelist = json.load(f)
            except json.JSONDecodeError:
                self._whitelist = {}

    def _save(self):
        self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.whitelist_file, 'w') as f:
            json.dump(self._whitelist, f, indent=2, ensure_ascii=False)

    def add(self, path: str, reason: str = ""):
        self._whitelist[path] = {
            "added_time": now_str(),
            "reason": reason,
        }
        self._save()
        self.log.info(f"添加白名单: {path}")

    def remove(self, path: str) -> bool:
        if path in self._whitelist:
            del self._whitelist[path]
            self._save()
            self.log.info(f"移除白名单: {path}")
            return True
        return False

    def is_whitelisted(self, path: str) -> bool:
        if path in self._whitelist:
            return True
        for wp in self._whitelist:
            if wp.endswith('*') and fnmatch.fnmatch(path, wp):
                return True
            if path.startswith(wp + '/'):
                return True
        return False

    def get_all(self) -> Dict[str, Dict]:
        return self._whitelist.copy()

    def clear(self):
        self._whitelist.clear()
        self._save()
        self.log.info("白名单已清空")


# ==================== 安全监控 ====================

class SecurityMonitor:
    def __init__(self, config: Config, log: LogManager):
        self.config = config
        self.log = log
        self.alerts_file = Path(ALERTS_FILE)
        self.alerts_file.parent.mkdir(parents=True, exist_ok=True)

    def assess_risk(self, path: str, event_type: str) -> str:
        for cf in SECURITY_CRITICAL_FILES:
            if path == cf or path.startswith(cf + '/'):
                return "critical"

        for hd in SECURITY_HIGH_DIRS:
            if path.startswith(hd + '/') or path == hd:
                return "high"

        if "/.ssh/" in path or path.endswith("/.ssh"):
            return "high"

        if "/var/lib/docker/" in path:
            return "medium"

        if event_type == "deleted" and path.startswith("/etc/"):
            return "high"

        return "low"

    def check_event(self, event: FileEvent) -> Optional[Alert]:
        if not self.config.alert_on_sensitive_changes:
            return None

        risk = self.assess_risk(event.path, event.event_type)
        event.risk_level = risk

        if risk in ("high", "critical"):
            alert = Alert(
                timestamp=event.timestamp,
                path=event.path,
                event_type=event.event_type,
                risk_level=risk,
                message=self._alert_msg(event, risk),
            )
            self._save_alert(alert)
            self.log.warning(f"安全告警 [{risk}]: {event.path} ({event.event_type})")
            return alert

        return None

    def _alert_msg(self, event: FileEvent, risk: str) -> str:
        types = {
            "created": "创建",
            "deleted": "删除",
            "modified": "修改",
            "moved_to": "移动到",
            "moved_from": "从...移出",
        }
        action = types.get(event.event_type, event.event_type)
        return f"{risk.upper()}: {action}敏感文件: {event.path}"

    def _save_alert(self, alert: Alert):
        try:
            with open(self.alerts_file, 'a') as f:
                f.write(alert.to_json() + '\n')
        except OSError:
            pass

    def get_alerts(self, limit: int = 100, risk: Optional[str] = None) -> List[Alert]:
        alerts = []
        if not self.alerts_file.exists():
            return alerts

        with open(self.alerts_file) as f:
            for line in reversed(f.readlines()):
                try:
                    data = json.loads(line.strip())
                    alert = Alert(**data)
                    if risk and alert.risk_level != risk:
                        continue
                    alerts.append(alert)
                    if len(alerts) >= limit:
                        break
                except json.JSONDecodeError:
                    continue

        return alerts

    def clear_alerts(self):
        if self.alerts_file.exists():
            self.alerts_file.unlink()
        self.log.info("告警已清空")


# ==================== 包管理器 ====================

class PackageManager:
    def __init__(self, config: Config, log: LogManager, events: EventStore,
                 whitelist: WhitelistManager):
        self.config = config
        self.log = log
        self.events = events
        self.whitelist = whitelist
        self.packages_file = Path(config.packages_file)
        self.packages_file.parent.mkdir(parents=True, exist_ok=True)
        self._packages: Dict[str, PackageRecord] = {}
        self._os = detect_os()
        self._load()

    def _load(self):
        if self.packages_file.exists():
            try:
                with open(self.packages_file) as f:
                    data = json.load(f)
                    for name, pkg_data in data.items():
                        self._packages[name] = PackageRecord(**pkg_data)
            except json.JSONDecodeError:
                self._packages = {}

    def _save(self):
        with open(self.packages_file, 'w') as f:
            json.dump(
                {name: pkg.to_dict() for name, pkg in self._packages.items()},
                f, indent=2, ensure_ascii=False
            )

    def get_installed_packages(self) -> List[str]:
        pkgs = []
        if self._os == "debian":
            rc, out, _ = run_cmd(["dpkg-query", "-W", "-f=${Package}\\n"])
            if rc == 0:
                pkgs = [p for p in out.strip().split('\n') if p]
        elif self._os == "redhat":
            rc, out, _ = run_cmd(["rpm", "-qa", "--queryformat=%{NAME}\\n"])
            if rc == 0:
                pkgs = [p for p in out.strip().split('\n') if p]
        return sorted(pkgs)

    def get_package_files(self, name: str) -> List[str]:
        files = []
        if self._os == "debian":
            rc, out, _ = run_cmd(["dpkg", "-L", name])
            if rc == 0:
                files = [f for f in out.strip().split('\n') if f]
        elif self._os == "redhat":
            rc, out, _ = run_cmd(["rpm", "-ql", name])
            if rc == 0:
                files = [f for f in out.strip().split('\n') if f]
        return files

    def get_package_config_files(self, name: str) -> List[str]:
        configs = []
        if self._os == "debian":
            rc, out, _ = run_cmd(["dpkg-query", "-W", "-f=${Conffiles}", name])
            if rc == 0:
                for line in out.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if parts and parts[0].startswith('/'):
                            configs.append(parts[0])
        return configs

    def get_package_services(self, name: str) -> List[str]:
        services = []
        rc, out, _ = run_cmd(["systemctl", "list-unit-files", "--no-pager", "--type=service"])
        if rc == 0:
            for line in out.split('\n'):
                if name.lower() in line.lower() and '.service' in line:
                    parts = line.split()
                    if parts:
                        services.append(parts[0])
        return services

    def track_package(self, name: str) -> Optional[PackageRecord]:
        if name in self._packages and not self._packages[name].removed:
            return self._packages[name]

        files = self.get_package_files(name)
        if not files:
            return None

        config_files = self.get_package_config_files(name)
        services = self.get_package_services(name)

        record = PackageRecord(
            name=name,
            install_time=now_str(),
            files=files,
            config_files=config_files,
            services=services,
        )

        self._packages[name] = record
        self._save()
        self.log.info(f"追踪新包: {name} ({len(files)} 文件)")
        return record

    def detect_new_packages(self, old_packages: List[str]) -> List[str]:
        current = set(self.get_installed_packages())
        old = set(old_packages)
        new = current - old
        for pkg in new:
            self.track_package(pkg)
        return sorted(new)

    def remove_package(self, name: str, purge: bool = True) -> bool:
        if name not in self._packages:
            self.log.warning(f"包未被追踪: {name}")

        pkg = self._packages.get(name)
        if pkg and pkg.removed:
            self.log.warning(f"包已被移除: {name}")
            return False

        self.log.info(f"开始移除包: {name}")

        # 停止服务
        if pkg:
            for svc in pkg.services:
                run_cmd(["systemctl", "stop", svc])
                run_cmd(["systemctl", "disable", svc])
                self.log.info(f"停止服务: {svc}")

        # 卸载
        if self._os == "debian":
            cmd = ["apt-get", "purge", "-y", name] if purge else ["apt-get", "remove", "-y", name]
            rc, _, err = run_cmd(cmd, timeout=120)
            if rc != 0:
                self.log.error(f"卸载失败: {err}")
                return False
            run_cmd(["apt-get", "autoremove", "-y"])
        elif self._os == "redhat":
            rc, _, err = run_cmd(["yum", "remove", "-y", name], timeout=120)
            if rc != 0:
                self.log.error(f"卸载失败: {err}")
                return False

        # 清理用户配置
        user_configs = [
            Path.home() / ".config" / name,
            Path.home() / ".local" / "share" / name,
            Path.home() / f".{name}",
        ]
        for uc in user_configs:
            if uc.exists():
                try:
                    if uc.is_dir():
                        shutil.rmtree(uc)
                    else:
                        uc.unlink()
                    self.log.info(f"清理用户配置: {uc}")
                except OSError as e:
                    self.log.warning(f"清理失败 {uc}: {e}")

        # 更新记录
        if pkg:
            pkg.removed = True
            pkg.remove_time = now_str()
            self._save()

        self.log.info(f"包已移除: {name}")
        return True

    def get_active(self) -> List[PackageRecord]:
        return [p for p in self._packages.values() if not p.removed]

    def get_all(self) -> Dict[str, PackageRecord]:
        return self._packages.copy()

    def get_package_for_path(self, path: str) -> Optional[str]:
        if self._os == "debian":
            rc, out, _ = run_cmd(["dpkg", "-S", path])
            if rc == 0 and ':' in out:
                return out.split(':')[0].strip()
        elif self._os == "redhat":
            rc, out, _ = run_cmd(["rpm", "-qf", path])
            if rc == 0:
                return out.strip()
        return None


# ==================== Docker 管理 ====================

class DockerManager:
    def __init__(self, config: Config, log: LogManager):
        self.config = config
        self.log = log
        self.docker_file = Path(DOCKER_FILE)
        self._containers: Dict[str, DockerContainer] = {}
        self._available = shutil.which("docker") is not None
        self._load()

    def _load(self):
        if self.docker_file.exists():
            try:
                with open(self.docker_file) as f:
                    data = json.load(f)
                    for cid, cdata in data.items():
                        self._containers[cid] = DockerContainer(**cdata)
            except json.JSONDecodeError:
                pass

    def _save(self):
        with open(self.docker_file, 'w') as f:
            json.dump(
                {cid: asdict(c) for cid, c in self._containers.items()},
                f, indent=2
            )

    @property
    def available(self) -> bool:
        return self._available

    def list_containers(self) -> List[Dict]:
        if not self._available:
            return []
        rc, out, _ = run_cmd(["docker", "ps", "-a", "--format", "json"])
        if rc != 0:
            return []
        containers = []
        for line in out.strip().split('\n'):
            if line:
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return containers

    def get_container_info(self, container_id: str) -> Optional[Dict]:
        if not self._available:
            return None
        rc, out, _ = run_cmd(["docker", "inspect", container_id])
        if rc == 0:
            try:
                data = json.loads(out)
                return data[0] if data else None
            except json.JSONDecodeError:
                return None
        return None

    def detect_new_containers(self, old_ids: List[str]) -> List[str]:
        if not self._available:
            return []
        current = self.list_containers()
        current_ids = [c.get("ID", "") for c in current]
        new = set(current_ids) - set(old_ids)
        for cid in new:
            info = self.get_container_info(cid)
            if info:
                container = DockerContainer(
                    container_id=cid,
                    name=info.get("Name", "").lstrip('/'),
                    image=info.get("Config", {}).get("Image", ""),
                    created=now_str(),
                    data_paths=[f"/var/lib/docker/containers/{cid}"],
                )
                self._containers[cid] = container
        self._save()
        return sorted(new)

    def stop_and_remove(self, container_id: str) -> bool:
        if not self._available:
            return False
        run_cmd(["docker", "stop", container_id])
        rc, _, _ = run_cmd(["docker", "rm", container_id])
        if rc == 0:
            if container_id in self._containers:
                self._containers[container_id].removed = True
                self._save()
            self.log.info(f"Docker容器已移除: {container_id}")
            return True
        return False

    def get_active(self) -> List[DockerContainer]:
        return [c for c in self._containers.values() if not c.removed]


# ==================== 状态管理 ====================

class StateManager:
    def __init__(self, config: Config, log: LogManager,
                 pkg_mgr: PackageManager, docker: DockerManager):
        self.config = config
        self.log = log
        self.pkg_mgr = pkg_mgr
        self.docker = docker
        self.state_dir = STATE_DIR
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def _should_ignore(self, path: str) -> bool:
        for p in self.config.ignore_patterns:
            if path.startswith(p + '/') or path == p:
                return True
        return False

    def capture(self, name: Optional[str] = None) -> SystemState:
        ts = now_str()
        version = name or ts.replace(':', '').replace(' ', '_')
        self.log.info(f"捕获系统状态: {version}")

        state = SystemState(timestamp=ts, config_version=version)

        # 文件状态
        state.files = self._capture_files()

        # 软件包
        state.packages = self.pkg_mgr.get_installed_packages()

        # sysctl
        state.sysctl = self._capture_sysctl()

        # 服务
        state.services = self._capture_services()

        # Docker 容器
        if self.docker.available:
            state.docker_containers = [c.get("ID", "") for c in self.docker.list_containers()]

        # 保存
        self._save_state(state)

        self.log.info(f"状态捕获完成: {len(state.files)} 文件, {len(state.packages)} 包")
        return state

    def _capture_files(self) -> Dict[str, Dict]:
        files = {}
        monitor_paths = list(self.config.monitor_paths)

        if self.config.monitor_user_dirs:
            monitor_paths.extend(USER_CONFIG_DIRS)

        for base_path in monitor_paths:
            base = Path(base_path)
            if not base.exists():
                continue

            count = 0
            try:
                for root, dirs, filenames in os.walk(base, followlinks=False):
                    # 过滤忽略的目录
                    dirs[:] = [d for d in dirs if not self._should_ignore(os.path.join(root, d))]

                    for fname in filenames:
                        fpath = os.path.join(root, fname)
                        if self._should_ignore(fpath):
                            continue

                        try:
                            st = os.stat(fpath)
                            checksum = None
                            if st.st_size < 5 * 1024 * 1024:  # <5MB 算 checksum
                                checksum = md5_file(Path(fpath))
                            files[fpath] = {
                                "size": st.st_size,
                                "mtime": st.st_mtime,
                                "checksum": checksum,
                            }
                            count += 1
                        except (PermissionError, OSError):
                            continue
            except PermissionError:
                continue

        return files

    def _capture_sysctl(self) -> Dict[str, str]:
        params = {}
        rc, out, _ = run_cmd(["sysctl", "-a"])
        if rc == 0:
            for line in out.split('\n'):
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    params[key.strip()] = value.strip()
        return params

    def _capture_services(self) -> Dict[str, str]:
        services = {}
        rc, out, _ = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-pager"])
        if rc == 0:
            for line in out.split('\n'):
                if '.service' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        name = parts[0]
                        status = parts[3]
                        services[name] = status
        return services

    def _save_state(self, state: SystemState):
        filename = f"state_{state.config_version}.json"
        path = self.state_dir / filename
        with open(path, 'w') as f:
            json.dump(state.to_dict(), f, indent=2, ensure_ascii=False)
        self.log.info(f"状态已保存: {path}")

    def load(self, name: str) -> Optional[SystemState]:
        filename = f"state_{name}.json"
        path = self.state_dir / filename

        if not path.exists():
            states = sorted(self.state_dir.glob("state_*.json"))
            if states:
                path = states[-1]
            else:
                return None

        try:
            with open(path) as f:
                data = json.load(f)
                return SystemState.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return None

    def compare(self, state1: SystemState, state2: SystemState) -> Dict:
        diff = {
            "added_files": [],
            "removed_files": [],
            "modified_files": [],
            "added_packages": [],
            "removed_packages": [],
            "sysctl_changes": {},
            "service_changes": {},
            "added_docker": [],
            "removed_docker": [],
        }

        # 文件差异
        f1 = set(state1.files.keys())
        f2 = set(state2.files.keys())

        diff["added_files"] = sorted(f2 - f1)
        diff["removed_files"] = sorted(f1 - f2)

        for path in f1 & f2:
            if state1.files[path].get("checksum") and state2.files[path].get("checksum"):
                if state1.files[path]["checksum"] != state2.files[path]["checksum"]:
                    diff["modified_files"].append({
                        "path": path,
                        "old_size": state1.files[path].get("size"),
                        "new_size": state2.files[path].get("size"),
                    })
            elif state1.files[path].get("mtime") != state2.files[path].get("mtime"):
                diff["modified_files"].append({
                    "path": path,
                    "old_size": state1.files[path].get("size"),
                    "new_size": state2.files[path].get("size"),
                })

        # 包差异
        p1 = set(state1.packages)
        p2 = set(state2.packages)
        diff["added_packages"] = sorted(p2 - p1)
        diff["removed_packages"] = sorted(p1 - p2)

        # sysctl 差异
        for key in set(state1.sysctl) | set(state2.sysctl):
            old = state1.sysctl.get(key)
            new = state2.sysctl.get(key)
            if old != new:
                diff["sysctl_changes"][key] = {"old": old, "new": new}

        # 服务差异
        for name in set(state1.services) | set(state2.services):
            old = state1.services.get(name)
            new = state2.services.get(name)
            if old != new:
                diff["service_changes"][name] = {"old": old, "new": new}

        # Docker 差异
        d1 = set(state1.docker_containers)
        d2 = set(state2.docker_containers)
        diff["added_docker"] = sorted(d2 - d1)
        diff["removed_docker"] = sorted(d1 - d2)

        return diff

    def list_states(self) -> List[str]:
        states = []
        for f in self.state_dir.glob("state_*.json"):
            name = f.stem.replace("state_", "")
            states.append(name)
        return sorted(states)

    def delete(self, name: str) -> bool:
        filename = f"state_{name}.json"
        path = self.state_dir / filename
        if path.exists():
            path.unlink()
            self.log.info(f"状态已删除: {name}")
            return True
        return False


# ==================== 配置管理 ====================

class ConfigBackupManager:
    def __init__(self, config: Config, log: LogManager):
        self.config = config
        self.log = log
        self.backup_dir = BASE_DIR / "config_backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def save_sysctl(self, name: Optional[str] = None) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        bname = name or f"sysctl_{ts}"
        path = self.backup_dir / f"{bname}.conf"

        rc, out, _ = run_cmd(["sysctl", "-a"])
        if rc == 0:
            with open(path, 'w') as f:
                f.write(f"# sysctl 备份 - {now_str()}\n\n")
                for line in sorted(out.split('\n')):
                    if '=' in line:
                        f.write(line + '\n')

        self.log.info(f"sysctl 已保存: {path}")
        return str(path)

    def restore_sysctl(self, name: str) -> bool:
        path = self.backup_dir / f"{name}.conf"
        if not path.exists():
            self.log.error(f"备份不存在: {name}")
            return False

        rc, _, _ = run_cmd(["sysctl", "-p", str(path)])
        if rc == 0:
            self.log.info(f"sysctl 已恢复: {name}")
            return True
        self.log.error("sysctl 恢复失败")
        return False

    def save_etc(self, name: Optional[str] = None) -> str:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        bname = name or f"etc_{ts}"
        backup_dir = self.backup_dir / bname
        backup_dir.mkdir(parents=True, exist_ok=True)

        important = [
            "passwd", "shadow", "group", "sudoers", "fstab",
            "hosts", "hostname", "crontab", "ssh", "systemd/system",
            "nginx", "apache2", "mysql", "postgresql", "redis",
            "sysctl.conf", "sysctl.d",
        ]

        etc = Path("/etc")
        for item in important:
            src = etc / item
            if not src.exists():
                continue
            dst = backup_dir / item
            try:
                if src.is_dir():
                    shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
                else:
                    shutil.copy2(src, dst)
            except (PermissionError, OSError) as e:
                self.log.warning(f"复制失败 {item}: {e}")

        self.log.info(f"/etc 已保存: {backup_dir}")
        return str(backup_dir)

    def restore_etc(self, name: str) -> bool:
        backup_dir = self.backup_dir / name
        if not backup_dir.exists():
            self.log.error(f"备份不存在: {name}")
            return False

        etc = Path("/etc")
        success = True

        for item in backup_dir.iterdir():
            dst = etc / item.name
            try:
                if dst.exists():
                    if dst.is_dir():
                        # 备份原文件再恢复
                        shutil.copytree(dst, dst.with_suffix('.bak'), dirs_exist_ok=True)
                        shutil.rmtree(dst)
                    else:
                        shutil.copy2(dst, dst.with_suffix('.bak'))

                if item.is_dir():
                    shutil.copytree(item, dst, symlinks=True)
                else:
                    shutil.copy2(item, dst)
            except (PermissionError, OSError) as e:
                self.log.error(f"恢复失败 {item.name}: {e}")
                success = False

        if success:
            self.log.info(f"/etc 已恢复: {name}")
        return success

    def list_backups(self) -> List[Dict]:
        backups = []
        for item in self.backup_dir.iterdir():
            if item.is_file() and item.suffix == ".conf":
                backups.append({
                    "name": item.stem,
                    "type": "sysctl",
                    "time": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
            elif item.is_dir():
                backups.append({
                    "name": item.name,
                    "type": "etc",
                    "time": datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
        return sorted(backups, key=lambda x: x["time"], reverse=True)

    def delete(self, name: str):
        for item in [self.backup_dir / f"{name}.conf", self.backup_dir / name]:
            if item.exists():
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
                self.log.info(f"备份已删除: {name}")


# ==================== 文件监控处理器 ====================

class MonitorHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, config: Config, log: LogManager, events: EventStore,
                 security: SecurityMonitor, whitelist: WhitelistManager,
                 pkg_mgr: PackageManager):
        self.config = config
        self.log = log
        self.events = events
        self.security = security
        self.whitelist = whitelist
        self.pkg_mgr = pkg_mgr
        self._recent = {}  # 简单的去重
        self._last_cleanup = time.time()

    def _should_ignore(self, path: str) -> bool:
        if self.whitelist.is_whitelisted(path):
            return True
        for p in self.config.ignore_patterns:
            if path.startswith(p + '/') or path == p:
                return True
        return False

    def _dedup(self, path: str, event_type: str) -> bool:
        key = (path, event_type)
        now = time.time()
        if key in self._recent and now - self._recent[key] < 1:
            return True
        self._recent[key] = now

        # 定期清理
        if now - self._last_cleanup > 60:
            self._recent = {k: v for k, v in self._recent.items() if now - v < 60}
            self._last_cleanup = now

        return False

    def _create_event(self, event_type: str, path: str, is_dir: bool) -> FileEvent:
        evt = FileEvent(
            timestamp=now_str(),
            event_type=event_type,
            path=path,
            is_directory=is_dir,
        )

        if not is_dir and Path(path).exists():
            try:
                st = Path(path).stat()
                evt.size = st.st_size
                if st.st_size < 5 * 1024 * 1024:
                    evt.checksum = md5_file(Path(path))
            except (PermissionError, OSError):
                pass

        # 尝试获取包名
        try:
            pkg = self.pkg_mgr.get_package_for_path(path)
            if pkg:
                evt.package = pkg
        except Exception:
            pass

        # 安全检查
        self.security.check_event(evt)

        return evt

    def on_created(self, event):
        if WATCHDOG_AVAILABLE:
            path = event.src_path
            if self._should_ignore(path) or self._dedup(path, "created"):
                return
            evt = self._create_event("created", path, event.is_directory)
            self.events.add(evt)
            self.log.debug(f"CREATE: {path}")

    def on_deleted(self, event):
        if WATCHDOG_AVAILABLE:
            path = event.src_path
            if self._should_ignore(path) or self._dedup(path, "deleted"):
                return
            evt = self._create_event("deleted", path, event.is_directory)
            self.events.add(evt)
            self.log.debug(f"DELETE: {path}")

    def on_modified(self, event):
        if WATCHDOG_AVAILABLE:
            path = event.src_path
            if self._should_ignore(path) or self._dedup(path, "modified"):
                return
            evt = self._create_event("modified", path, event.is_directory)
            self.events.add(evt)
            self.log.debug(f"MODIFY: {path}")

    def on_moved(self, event):
        if WATCHDOG_AVAILABLE:
            src = event.src_path
            dst = event.dest_path

            if not self._should_ignore(src):
                if not self._dedup(src, "moved_from"):
                    evt = self._create_event("moved_from", src, event.is_directory)
                    self.events.add(evt)

            if not self._should_ignore(dst):
                if not self._dedup(dst, "moved_to"):
                    evt = self._create_event("moved_to", dst, event.is_directory)
                    self.events.add(evt)


# ==================== 守护进程 ====================

class DaemonService:
    def __init__(self):
        self.config = Config.load()
        self.log = LogManager(self.config)
        self.events = EventStore(self.config, self.log)
        self.whitelist = WhitelistManager(self.config, self.log)
        self.security = SecurityMonitor(self.config, self.log)
        self.pkg_mgr = PackageManager(self.config, self.log, self.events, self.whitelist)
        self.docker = DockerManager(self.config, self.log)
        self.state_mgr = StateManager(self.config, self.log, self.pkg_mgr, self.docker)
        self.cfg_mgr = ConfigBackupManager(self.config, self.log)

        self._observer = None
        self._stop_event = Event()
        self._monitor_thread = None
        self._package_thread = None
        self._cleanup_thread = None

    def _daemonize(self):
        """守护进程化"""
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            self.log.error(f"fork 失败: {e}")
            sys.exit(1)

        os.chdir('/')
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            self.log.error(f"二次 fork 失败: {e}")
            sys.exit(1)

        # 重定向标准流
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # 写 PID 文件
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PID_FILE, 'w') as f:
            f.write(str(os.getpid()))

        atexit.register(self._cleanup_pid)

    def _cleanup_pid(self):
        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass

    def is_running(self) -> bool:
        if not PID_FILE.exists():
            return False
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            return False

    def get_pid(self) -> Optional[int]:
        if PID_FILE.exists():
            try:
                with open(PID_FILE) as f:
                    return int(f.read().strip())
            except ValueError:
                pass
        return None

    def start(self, daemon: bool = True):
        if self.is_running():
            print(f"监控已在运行，PID: {self.get_pid()}")
            return False

        if not WATCHDOG_AVAILABLE:
            print("错误: watchdog 未安装")
            print("请安装: pip install watchdog")
            return False

        if daemon:
            print("正在启动监控守护进程...")
            self._daemonize()
        else:
            PID_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))

        self.log.info("启动文件监控...")

        # 启动文件监控
        handler = MonitorHandler(
            self.config, self.log, self.events,
            self.security, self.whitelist, self.pkg_mgr
        )

        self._observer = Observer()
        for path in self.config.monitor_paths:
            if Path(path).exists():
                try:
                    self._observer.schedule(handler, path, recursive=True)
                    self.log.info(f"监控: {path}")
                except Exception as e:
                    self.log.warning(f"无法监控 {path}: {e}")

        if self.config.monitor_user_dirs:
            for path in USER_CONFIG_DIRS:
                if Path(path).exists():
                    try:
                        self._observer.schedule(handler, path, recursive=True)
                        self.log.info(f"监控: {path}")
                    except Exception as e:
                        self.log.warning(f"无法监控 {path}: {e}")

        self._observer.start()

        # 包安装监控线程
        self._package_thread = Thread(target=self._monitor_packages, daemon=True)
        self._package_thread.start()

        # 定期清理线程
        self._cleanup_thread = Thread(target=self._periodic_cleanup, daemon=True)
        self._cleanup_thread.start()

        self.log.info("监控已启动")

        if not daemon:
            print(f"监控已启动，PID: {os.getpid()}")

        # 主循环
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(1)
        except KeyboardInterrupt:
            self.log.info("收到中断信号")

        self.stop()
        return True

    def stop(self):
        self.log.info("停止监控...")

        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)

        self._stop_event.set()

        self._cleanup_pid()
        self.log.info("监控已停止")

    def _monitor_packages(self):
        """监控包安装"""
        last_packages = set(self.pkg_mgr.get_installed_packages())
        while not self._stop_event.is_set():
            try:
                time.sleep(30)
                current = set(self.pkg_mgr.get_installed_packages())
                new = current - last_packages
                removed = last_packages - current

                for pkg in new:
                    self.pkg_mgr.track_package(pkg)
                    self.log.info(f"检测到新安装包: {pkg}")

                for pkg in removed:
                    self.log.info(f"检测到包被移除: {pkg}")

                last_packages = current
            except Exception as e:
                self.log.error(f"包监控错误: {e}")

    def _periodic_cleanup(self):
        """定期清理"""
        while not self._stop_event.is_set():
            try:
                time.sleep(3600)  # 每小时
                self.log.rotate_if_needed()
                self.events.cleanup_old()
            except Exception as e:
                self.log.error(f"清理错误: {e}")

    def enable_autostart(self) -> bool:
        """设置开机自启 (systemd)"""
        service_file = Path("/etc/systemd/system/file-monitor.service")
        script_path = Path(__file__).resolve()

        content = f"""[Unit]
Description=File System Monitor Service
After=network.target

[Service]
Type=forking
ExecStart=/usr/bin/python3 {script_path} start
ExecStop=/usr/bin/python3 {script_path} stop
PIDFile={PID_FILE}
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""

        try:
            service_file.parent.mkdir(parents=True, exist_ok=True)
            with open(service_file, 'w') as f:
                f.write(content)

            run_cmd(["systemctl", "daemon-reload"])
            rc, _, _ = run_cmd(["systemctl", "enable", "file-monitor.service"])
            if rc == 0:
                self.log.info("开机自启已启用")
                return True
        except OSError as e:
            self.log.error(f"设置开机自启失败: {e}")
        return False

    def disable_autostart(self) -> bool:
        """禁用开机自启"""
        service_file = Path("/etc/systemd/system/file-monitor.service")

        try:
            run_cmd(["systemctl", "disable", "file-monitor.service"])
            if service_file.exists():
                service_file.unlink()
            run_cmd(["systemctl", "daemon-reload"])
            self.log.info("开机自启已禁用")
            return True
        except OSError as e:
            self.log.error(f"禁用开机自启失败: {e}")
        return False

    def is_autostart_enabled(self) -> bool:
        """检查开机自启是否启用"""
        rc, out, _ = run_cmd(["systemctl", "is-enabled", "file-monitor.service"])
        return rc == 0 and "enabled" in out


# ==================== 交互式清理 ====================

class InteractiveCleaner:
    def __init__(self, service: DaemonService):
        self.svc = service

    def run(self):
        print("\n" + "=" * 50)
        print("  智能清理向导")
        print("=" * 50)

        stats = self.svc.events.stats()
        print(f"\n当前事件总数: {stats.get('total', 0)}")

        packages = self.svc.pkg_mgr.get_active()
        if packages:
            print(f"追踪的软件包: {len(packages)}")
            for pkg in packages:
                print(f"  - {pkg.name} ({len(pkg.files)} 文件)")

        docker = self.svc.docker.get_active()
        if docker:
            print(f"Docker 容器: {len(docker)}")
            for c in docker:
                print(f"  - {c.name} ({c.image})")

        new_files = self.svc.events.query(event_type="created", limit=100)
        print(f"\n新增文件/目录 (最近100条): {len(new_files)}")

        print("\n请选择清理操作:")
        print("  1. 卸载软件包")
        print("  2. 清理 Docker 容器")
        print("  3. 删除新增文件/目录")
        print("  4. 清空所有事件记录")
        print("  0. 返回")

        choice = input("\n请输入选项: ").strip()

        if choice == "1":
            self._clean_packages()
        elif choice == "2":
            self._clean_docker()
        elif choice == "3":
            self._clean_files()
        elif choice == "4":
            self._clear_events()

    def _clean_packages(self):
        packages = self.svc.pkg_mgr.get_active()
        if not packages:
            print("\n没有追踪的软件包")
            return

        print("\n=== 可卸载的软件包 ===")
        for i, pkg in enumerate(packages, 1):
            print(f"  {i}. {pkg.name} ({len(pkg.files)} 文件)")

        choice = input("\n输入要卸载的包编号（多个用空格分隔）: ").strip()
        if not choice:
            return

        for num_str in choice.split():
            try:
                idx = int(num_str) - 1
                if 0 <= idx < len(packages):
                    pkg = packages[idx]
                    confirm = input(f"确认彻底卸载 {pkg.name}? (y/N): ").strip().lower()
                    if confirm == 'y':
                        if self.svc.pkg_mgr.remove_package(pkg.name):
                            print(f"✓ {pkg.name} 已彻底卸载")
                        else:
                            print(f"✗ {pkg.name} 卸载失败")
            except (ValueError, IndexError):
                continue

    def _clean_docker(self):
        containers = self.svc.docker.get_active()
        if not containers:
            print("\n没有追踪的 Docker 容器")
            return

        print("\n=== Docker 容器 ===")
        for i, c in enumerate(containers, 1):
            print(f"  {i}. {c.name} ({c.image})")

        choice = input("\n输入要删除的容器编号: ").strip()
        if not choice:
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(containers):
                c = containers[idx]
                confirm = input(f"确认停止并删除容器 {c.name}? (y/N): ").strip().lower()
                if confirm == 'y':
                    if self.svc.docker.stop_and_remove(c.container_id):
                        print(f"✓ 容器 {c.name} 已删除")
                    else:
                        print(f"✗ 删除失败")
        except (ValueError, IndexError):
            pass

    def _clean_files(self):
        events = self.svc.events.query(event_type="created", limit=200)
        if not events:
            print("\n没有新增文件")
            return

        # 过滤掉包文件和已删除的
        files = [e for e in events if not e.package and Path(e.path).exists()]

        print(f"\n=== 新增文件 ({len(files)} 个) ===")
        for i, evt in enumerate(files[:50], 1):
            icon = "📁" if evt.is_directory else "📄"
            risk = ""
            if evt.risk_level == "high":
                risk = " [HIGH]"
            elif evt.risk_level == "critical":
                risk = " [CRITICAL]"
            print(f"  {i:3d}. {icon} {evt.path}{risk}")

        if len(files) > 50:
            print(f"  ... 还有 {len(files) - 50} 个")

        print("\n操作:")
        print("  输入编号删除单个")
        print("  输入 'all' 删除全部（危险！）")
        print("  输入 'add' 添加到白名单")
        print("  直接回车返回")

        choice = input("\n请选择: ").strip()

        if choice == 'all':
            confirm = input("⚠️ 确认删除所有新增文件? 这可能影响系统! (yes/N): ").strip().lower()
            if confirm == 'yes':
                count = 0
                for evt in files:
                    try:
                        if evt.is_directory:
                            shutil.rmtree(evt.path)
                        else:
                            Path(evt.path).unlink()
                        count += 1
                    except OSError:
                        pass
                print(f"已删除 {count} 个文件/目录")
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                evt = files[idx]
                confirm = input(f"确认删除 {evt.path}? (y/N): ").strip().lower()
                if confirm == 'y':
                    try:
                        if evt.is_directory:
                            shutil.rmtree(evt.path)
                        else:
                            Path(evt.path).unlink()
                        print("✓ 已删除")
                    except OSError as e:
                        print(f"✗ 删除失败: {e}")
        elif choice == 'add':
            idx_input = input("输入要添加白名单的编号: ").strip()
            if idx_input.isdigit():
                idx = int(idx_input) - 1
                if 0 <= idx < len(files):
                    path = files[idx].path
                    self.svc.whitelist.add(path)
                    print(f"✓ 已添加白名单: {path}")

    def _clear_events(self):
        confirm = input("确认清空所有事件记录? (y/N): ").strip().lower()
        if confirm == 'y':
            self.svc.events.clear()
            print("✓ 事件已清空")


# ==================== 交互式菜单 ====================

class InteractiveMenu:
    def __init__(self):
        self.svc = DaemonService()
        self.cleaner = InteractiveCleaner(self.svc)

    def run(self):
        while True:
            self._clear_screen()
            self._show_header()
            self._show_status()

            print("\n=== 主菜单 ===")
            print("  1. 启动监控守护进程")
            print("  2. 停止监控")
            print("  3. 查看监控状态")
            print("  4. 智能清理新增项目")
            print("  5. 系统状态管理")
            print("  6. 安全告警")
            print("  7. 软件包管理")
            print("  8. 配置备份")
            print("  9. 白名单管理")
            print("  10. 查看事件")
            print("  11. 开机自启设置")
            print("  0. 退出")

            choice = input("\n请选择 (0-11): ").strip()

            if choice == '0':
                print("再见！")
                break
            elif choice == '1':
                self._start_monitor()
            elif choice == '2':
                self._stop_monitor()
            elif choice == '3':
                self._show_detail_status()
            elif choice == '4':
                self.cleaner.run()
            elif choice == '5':
                self._state_menu()
            elif choice == '6':
                self._alerts_menu()
            elif choice == '7':
                self._packages_menu()
            elif choice == '8':
                self._config_menu()
            elif choice == '9':
                self._whitelist_menu()
            elif choice == '10':
                self._events_menu()
            elif choice == '11':
                self._autostart_menu()

            input("\n按回车继续...")

    def _clear_screen(self):
        os.system('clear' if os.name != 'nt' else 'cls')

    def _show_header(self):
        print("=" * 60)
        print("  文件系统监控与清理工具")
        print("  File System Monitor & Cleaner")
        print("=" * 60)

    def _show_status(self):
        running = self.svc.is_running()
        pid = self.svc.get_pid()
        status = f"运行中 (PID: {pid})" if running else "已停止"
        color = "✓" if running else "✗"
        print(f"\n  监控状态: {color} {status}")

        stats = self.svc.events.stats()
        print(f"  事件总数: {stats.get('total', 0)}")
        print(f"  追踪包: {len(self.svc.pkg_mgr.get_active())}")

    def _start_monitor(self):
        if self.svc.is_running():
            print("监控已在运行")
            return

        daemon = input("后台守护进程运行? (Y/n): ").strip().lower()
        if daemon in ('', 'y', 'yes'):
            self.svc.start(daemon=True)
            print("守护进程正在启动...")
            time.sleep(2)
            if self.svc.is_running():
                print(f"✓ 启动成功，PID: {self.svc.get_pid()}")
            else:
                print("✗ 启动失败，请检查日志")
        else:
            print("前台运行，按 Ctrl+C 停止...")
            try:
                self.svc.start(daemon=False)
            except KeyboardInterrupt:
                pass

    def _stop_monitor(self):
        pid = self.svc.get_pid()
        if not pid:
            print("监控未运行")
            return

        try:
            os.kill(pid, signal.SIGTERM)
            print("正在停止...")
            for _ in range(10):
                time.sleep(0.5)
                if not self.svc.is_running():
                    break
            if self.svc.is_running():
                os.kill(pid, signal.SIGKILL)
            print("✓ 已停止")
        except OSError as e:
            print(f"停止失败: {e}")

    def _show_detail_status(self):
        print("\n=== 详细状态 ===")
        running = self.svc.is_running()
        print(f"监控状态: {'运行中' if running else '已停止'}")
        if running:
            print(f"PID: {self.svc.get_pid()}")

        stats = self.svc.events.stats()
        print(f"\n事件统计:")
        print(f"  总数: {stats.get('total', 0)}")
        by_type = stats.get('by_type', {})
        for t, c in by_type.items():
            print(f"  {t}: {c}")

        alerts = self.svc.security.get_alerts(limit=10)
        print(f"\n安全告警: {len(alerts)}")

        packages = self.svc.pkg_mgr.get_active()
        print(f"追踪包: {len(packages)}")

        docker = self.svc.docker.get_active()
        print(f"Docker 容器: {len(docker)}")

    def _state_menu(self):
        while True:
            print("\n--- 系统状态管理 ---")
            print("  1. 捕获当前状态")
            print("  2. 列出所有状态")
            print("  3. 比较两个状态")
            print("  4. 删除状态")
            print("  0. 返回")

            choice = input("请选择: ").strip()
            if choice == '0':
                break
            elif choice == '1':
                name = input("状态名称 (留空自动生成): ").strip() or None
                state = self.svc.state_mgr.capture(name)
                print(f"✓ 状态已保存: {state.config_version}")
            elif choice == '2':
                states = self.svc.state_mgr.list_states()
                if states:
                    print("保存的状态:")
                    for s in states:
                        print(f"  - {s}")
                else:
                    print("没有保存的状态")
            elif choice == '3':
                s1 = input("第一个状态名称: ").strip()
                s2 = input("第二个状态名称: ").strip()
                state1 = self.svc.state_mgr.load(s1)
                state2 = self.svc.state_mgr.load(s2)
                if not state1 or not state2:
                    print("状态不存在")
                    continue
                diff = self.svc.state_mgr.compare(state1, state2)
                print(f"\n新增文件: {len(diff['added_files'])}")
                if diff['added_files'][:20]:
                    for f in diff['added_files'][:20]:
                        print(f"  + {f}")
                print(f"删除文件: {len(diff['removed_files'])}")
                print(f"修改文件: {len(diff['modified_files'])}")
                print(f"新增包: {diff['added_packages']}")
                print(f"删除包: {diff['removed_packages']}")
                print(f"sysctl 变化: {len(diff['sysctl_changes'])}")
                print(f"服务变化: {len(diff['service_changes'])}")
            elif choice == '4':
                name = input("要删除的状态名称: ").strip()
                if self.svc.state_mgr.delete(name):
                    print("✓ 已删除")
                else:
                    print("状态不存在")

    def _alerts_menu(self):
        while True:
            print("\n--- 安全告警 ---")
            alerts = self.svc.security.get_alerts(limit=20)
            print(f"告警总数: {len(alerts)} (显示最近20条)")
            for a in alerts[:20]:
                print(f"  [{a.risk_level}] {a.timestamp}")
                print(f"    {a.message}")

            print("\n  1. 查看高危告警")
            print("  2. 清空所有告警")
            print("  0. 返回")

            choice = input("请选择: ").strip()
            if choice == '0':
                break
            elif choice == '1':
                high = self.svc.security.get_alerts(limit=20, risk="high")
                critical = self.svc.security.get_alerts(limit=20, risk="critical")
                print(f"\n高危告警 ({len(high)}):")
                for a in high:
                    print(f"  {a.timestamp} - {a.message}")
                print(f"\n严重告警 ({len(critical)}):")
                for a in critical:
                    print(f"  {a.timestamp} - {a.message}")
            elif choice == '2':
                confirm = input("确认清空所有告警? (y/N): ").strip().lower()
                if confirm == 'y':
                    self.svc.security.clear_alerts()
                    print("✓ 告警已清空")

    def _packages_menu(self):
        while True:
            print("\n--- 软件包管理 ---")
            packages = self.svc.pkg_mgr.get_active()
            print(f"追踪的包: {len(packages)}")
            for i, pkg in enumerate(packages, 1):
                print(f"  {i}. {pkg.name} ({len(pkg.files)} 文件)")

            print("\n  1. 刷新包列表")
            print("  2. 卸载软件包")
            print("  3. 查看包详情")
            print("  0. 返回")

            choice = input("请选择: ").strip()
            if choice == '0':
                break
            elif choice == '1':
                self.svc.pkg_mgr.get_installed_packages()
                print("✓ 已刷新")
            elif choice == '2':
                idx = input("要卸载的包编号: ").strip()
                if idx.isdigit():
                    i = int(idx) - 1
                    if 0 <= i < len(packages):
                        pkg = packages[i]
                        confirm = input(f"彻底卸载 {pkg.name}? (y/N): ").strip().lower()
                        if confirm == 'y':
                            if self.svc.pkg_mgr.remove_package(pkg.name):
                                print("✓ 已卸载")
                            else:
                                print("✗ 卸载失败")
            elif choice == '3':
                idx = input("包编号: ").strip()
                if idx.isdigit():
                    i = int(idx) - 1
                    if 0 <= i < len(packages):
                        pkg = packages[i]
                        print(f"\n包名: {pkg.name}")
                        print(f"安装时间: {pkg.install_time}")
                        print(f"文件数: {len(pkg.files)}")
                        print(f"配置文件: {len(pkg.config_files)}")
                        print(f"服务: {', '.join(pkg.services) or '无'}")

    def _config_menu(self):
        while True:
            print("\n--- 配置备份 ---")
            backups = self.svc.cfg_mgr.list_backups()
            print(f"备份数: {len(backups)}")
            for b in backups:
                print(f"  [{b['type']}] {b['name']} - {b['time']}")

            print("\n  1. 保存 sysctl")
            print("  2. 保存 /etc 配置")
            print("  3. 恢复配置")
            print("  4. 删除备份")
            print("  0. 返回")

            choice = input("请选择: ").strip()
            if choice == '0':
                break
            elif choice == '1':
                name = input("备份名称 (留空自动): ").strip() or None
                path = self.svc.cfg_mgr.save_sysctl(name)
                print(f"✓ 已保存: {path}")
            elif choice == '2':
                name = input("备份名称 (留空自动): ").strip() or None
                path = self.svc.cfg_mgr.save_etc(name)
                print(f"✓ 已保存: {path}")
            elif choice == '3':
                name = input("备份名称: ").strip()
                if name:
                    if self.svc.cfg_mgr.restore_sysctl(name):
                        print("✓ sysctl 已恢复")
                    if (self.svc.cfg_mgr.backup_dir / name).is_dir():
                        confirm = input("恢复 /etc 配置? (y/N): ").strip().lower()
                        if confirm == 'y':
                            if self.svc.cfg_mgr.restore_etc(name):
                                print("✓ /etc 已恢复")
            elif choice == '4':
                name = input("要删除的备份名称: ").strip()
                if name:
                    self.svc.cfg_mgr.delete(name)
                    print("✓ 已删除")

    def _whitelist_menu(self):
        while True:
            print("\n--- 白名单管理 ---")
            wl = self.svc.whitelist.get_all()
            print(f"白名单项: {len(wl)}")
            for path, info in wl.items():
                print(f"  {path}")

            print("\n  1. 添加路径")
            print("  2. 移除路径")
            print("  3. 清空")
            print("  0. 返回")

            choice = input("请选择: ").strip()
            if choice == '0':
                break
            elif choice == '1':
                path = input("路径: ").strip()
                reason = input("原因 (可选): ").strip()
                if path:
                    self.svc.whitelist.add(path, reason)
                    print("✓ 已添加")
            elif choice == '2':
                path = input("路径: ").strip()
                if path:
                    if self.svc.whitelist.remove(path):
                        print("✓ 已移除")
                    else:
                        print("不在白名单中")
            elif choice == '3':
                confirm = input("确认清空? (y/N): ").strip().lower()
                if confirm == 'y':
                    self.svc.whitelist.clear()
                    print("✓ 已清空")

    def _events_menu(self):
        print("\n--- 事件查看 ---")
        print("  1. 所有事件 (最近100)")
        print("  2. 新增文件")
        print("  3. 删除文件")
        print("  4. 修改文件")
        print("  5. 高危事件")

        choice = input("请选择: ").strip()
        limit = 100

        if choice == '1':
            events = self.svc.events.query(limit=limit, reverse=True)
        elif choice == '2':
            events = self.svc.events.query(event_type="created", limit=limit, reverse=True)
        elif choice == '3':
            events = self.svc.events.query(event_type="deleted", limit=limit, reverse=True)
        elif choice == '4':
            events = self.svc.events.query(event_type="modified", limit=limit, reverse=True)
        elif choice == '5':
            events = self.svc.events.query(risk_level="high", limit=limit, reverse=True)
            events += self.svc.events.query(risk_level="critical", limit=limit, reverse=True)
        else:
            return

        print(f"\n共 {len(events)} 条事件:")
        for evt in events[:50]:
            icon = "📁" if evt.is_directory else "📄"
            risk = f" [{evt.risk_level}]" if evt.risk_level != "low" else ""
            print(f"  {icon} {evt.timestamp} [{evt.event_type}]{risk} {evt.path}")

        if len(events) > 50:
            print(f"  ... 还有 {len(events) - 50} 条")

    def _autostart_menu(self):
        while True:
            print("\n--- 开机自启设置 ---")
            enabled = self.svc.is_autostart_enabled()
            print(f"当前状态: {'已启用' if enabled else '未启用'}")

            print("\n  1. 启用开机自启")
            print("  2. 禁用开机自启")
            print("  0. 返回")

            choice = input("请选择: ").strip()
            if choice == '0':
                break
            elif choice == '1':
                if self.svc.enable_autostart():
                    print("✓ 开机自启已启用")
                else:
                    print("✗ 启用失败")
            elif choice == '2':
                if self.svc.disable_autostart():
                    print("✓ 开机自启已禁用")
                else:
                    print("✗ 禁用失败")


# ==================== CLI 入口 ====================

def main():
    check_root()

    parser = argparse.ArgumentParser(
        description="文件系统监控与清理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s start              # 启动守护进程
  %(prog)s stop               # 停止
  %(prog)s status             # 状态
  %(prog)s capture -n before  # 捕获状态
  %(prog)s diff before after  # 比较状态
  %(prog)s remove nginx       # 彻底卸载包
  %(prog)s alerts             # 查看告警
  %(prog)s menu               # 交互式菜单
        """
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("start", help="启动监控守护进程")
    sub.add_parser("stop", help="停止监控")
    sub.add_parser("status", help="查看状态")
    sub.add_parser("menu", help="交互式菜单")

    p = sub.add_parser("capture", help="捕获系统状态")
    p.add_argument("-n", "--name", help="状态名称")

    p = sub.add_parser("diff", help="比较两个状态")
    p.add_argument("state1")
    p.add_argument("state2")

    p = sub.add_parser("remove", help="彻底卸载软件包")
    p.add_argument("package")
    p.add_argument("--no-purge", action="store_true")

    sub.add_parser("clean", help="交互式清理")
    sub.add_parser("alerts", help="查看安全告警")
    sub.add_parser("packages", help="查看追踪的包")
    sub.add_parser("states", help="列出状态")

    p = sub.add_parser("events", help="查看事件")
    p.add_argument("-t", "--type")
    p.add_argument("-p", "--path")
    p.add_argument("-l", "--limit", type=int, default=50)

    p = sub.add_parser("config", help="配置备份")
    p.add_argument("action", choices=["save", "restore", "list", "delete"])
    p.add_argument("-n", "--name")
    p.add_argument("-t", "--type", choices=["sysctl", "etc"], default="sysctl")

    p = sub.add_parser("whitelist", help="白名单")
    p.add_argument("action", choices=["list", "add", "remove", "clear"])
    p.add_argument("-p", "--path")

    p = sub.add_parser("autostart", help="开机自启管理")
    p.add_argument("action", choices=["enable", "disable", "status"])

    args = parser.parse_args()

    if not args.command:
        InteractiveMenu().run()
        return

    svc = DaemonService()

    if args.command == "start":
        svc.start(daemon=True)
    elif args.command == "stop":
        pid = svc.get_pid()
        if pid:
            os.kill(pid, signal.SIGTERM)
            print("正在停止...")
            time.sleep(2)
            if svc.is_running():
                os.kill(pid, signal.SIGKILL)
            print("已停止")
        else:
            print("未运行")
    elif args.command == "status":
        running = svc.is_running()
        print(f"状态: {'运行中' if running else '已停止'}")
        if running:
            print(f"PID: {svc.get_pid()}")
        stats = svc.events.stats()
        print(f"事件: {stats.get('total', 0)}")
        print(f"追踪包: {len(svc.pkg_mgr.get_active())}")
        alerts = svc.security.get_alerts(limit=10)
        print(f"告警: {len(alerts)}")
    elif args.command == "menu":
        InteractiveMenu().run()
    elif args.command == "capture":
        state = svc.state_mgr.capture(args.name)
        print(f"状态已保存: {state.config_version}")
        print(f"文件: {len(state.files)}, 包: {len(state.packages)}")
    elif args.command == "diff":
        s1 = svc.state_mgr.load(args.state1)
        s2 = svc.state_mgr.load(args.state2)
        if not s1:
            print(f"状态不存在: {args.state1}")
            return
        if not s2:
            print(f"状态不存在: {args.state2}")
            return
        diff = svc.state_mgr.compare(s1, s2)
        print(f"\n新增文件: {len(diff['added_files'])}")
        for f in diff['added_files'][:30]:
            print(f"  + {f}")
        if len(diff['added_files']) > 30:
            print(f"  ... 还有 {len(diff['added_files']) - 30} 个")
        print(f"\n删除文件: {len(diff['removed_files'])}")
        print(f"修改文件: {len(diff['modified_files'])}")
        print(f"\n新增包: {diff['added_packages']}")
        print(f"删除包: {diff['removed_packages']}")
        print(f"\nsysctl 变化: {len(diff['sysctl_changes'])}")
        print(f"服务变化: {len(diff['service_changes'])}")
    elif args.command == "remove":
        if svc.pkg_mgr.remove_package(args.package, not args.no_purge):
            print(f"✓ {args.package} 已彻底移除")
        else:
            print(f"✗ 移除失败")
    elif args.command == "clean":
        InteractiveCleaner(svc).run()
    elif args.command == "alerts":
        alerts = svc.security.get_alerts(limit=50)
        print(f"告警 ({len(alerts)}):")
        for a in alerts:
            print(f"  [{a.risk_level}] {a.timestamp} - {a.message}")
    elif args.command == "packages":
        pkgs = svc.pkg_mgr.get_active()
        print(f"追踪的包 ({len(pkgs)}):")
        for p in pkgs:
            print(f"  {p.name} ({len(p.files)} 文件, {len(p.services)} 服务)")
    elif args.command == "states":
        states = svc.state_mgr.list_states()
        print("保存的状态:")
        for s in states:
            print(f"  {s}")
    elif args.command == "events":
        events = svc.events.query(
            event_type=args.type,
            path_prefix=args.path,
            limit=args.limit,
            reverse=True
        )
        print(f"事件 ({len(events)}):")
        for e in events:
            risk = f" [{e.risk_level}]" if e.risk_level != "low" else ""
            print(f"  {e.timestamp} [{e.event_type}]{risk} {e.path}")
    elif args.command == "config":
        if args.action == "save":
            if args.type == "sysctl":
                path = svc.cfg_mgr.save_sysctl(args.name)
                print(f"已保存: {path}")
            elif args.type == "etc":
                path = svc.cfg_mgr.save_etc(args.name)
                print(f"已保存: {path}")
        elif args.action == "restore":
            if not args.name:
                print("请指定名称")
                return
            if args.type == "sysctl":
                if svc.cfg_mgr.restore_sysctl(args.name):
                    print("已恢复")
            elif args.type == "etc":
                if svc.cfg_mgr.restore_etc(args.name):
                    print("已恢复")
        elif args.action == "list":
            backups = svc.cfg_mgr.list_backups()
            for b in backups:
                print(f"  [{b['type']}] {b['name']} - {b['time']}")
        elif args.action == "delete":
            if args.name:
                svc.cfg_mgr.delete(args.name)
                print("已删除")
    elif args.command == "whitelist":
        if args.action == "list":
            wl = svc.whitelist.get_all()
            for path, info in wl.items():
                print(f"  {path}")
        elif args.action == "add":
            if args.path:
                svc.whitelist.add(args.path)
                print("已添加")
        elif args.action == "remove":
            if args.path:
                svc.whitelist.remove(args.path)
                print("已移除")
        elif args.action == "clear":
            svc.whitelist.clear()
            print("已清空")
    elif args.command == "autostart":
        if args.action == "enable":
            if svc.enable_autostart():
                print("✓ 开机自启已启用")
            else:
                print("✗ 启用失败")
        elif args.action == "disable":
            if svc.disable_autostart():
                print("✓ 开机自启已禁用")
            else:
                print("✗ 禁用失败")
        elif args.action == "status":
            enabled = svc.is_autostart_enabled()
            print(f"开机自启: {'已启用' if enabled else '未启用'}")


if __name__ == "__main__":
    main()
