"""宿主机静态信息。"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import uuid
from dataclasses import dataclass, field


@dataclass(slots=True)
class HostInfo:
    """宿主机的静态事实，用于注册、审计或诊断。"""

    hostname: str = ""
    os: str = ""
    platform: str = ""
    platform_version: str = ""
    kernel_version: str = ""
    arch: str = ""
    host_id: str = ""
    mac_addrs: list[str] = field(default_factory=list)
    virtualization_system: str = ""
    virtualization_role: str = ""
    cpu_model_name: str = ""
    cpu_cores: int = 0
    total_memory: int = 0
    total_disk: int = 0


def new_host_info() -> HostInfo:
    """采集当前宿主机的静态信息，避免引入 psutil 等额外依赖。"""

    # platform.system() 使用 Python 命名，后续网关或日志可按需要做归一。
    system = platform.system().lower()
    # uuid.getnode() 可作为轻量 host_id 兜底；真实生产可由部署层覆盖更稳定 ID。
    node = uuid.getnode()
    # MAC 地址按标准冒号格式输出，便于与 Go 版 HostInfo 字段对齐。
    mac = _format_mac(node)
    # 根分区容量是静态诊断信息，读取失败时保持 0 而不是阻断服务启动。
    total_disk = _root_disk_total()
    # 总内存在不同 Unix 上获取方式不同；不可得时返回 0 保持宽容。
    total_memory = _total_memory()
    return HostInfo(
        hostname=socket.gethostname(),
        os=system,
        platform=platform.platform(),
        platform_version=platform.version(),
        kernel_version=platform.release(),
        arch=platform.machine(),
        host_id=f"{node:012x}",
        mac_addrs=[mac] if mac else [],
        cpu_model_name=platform.processor(),
        cpu_cores=os.cpu_count() or 0,
        total_memory=total_memory,
        total_disk=total_disk,
    )


def _format_mac(node: int) -> str:
    # uuid.getnode 返回 48 bit 整数；全部为 0 时不输出无效 MAC。
    if node <= 0:
        return ""
    # 拆成六段十六进制，保持和 Go net.HardwareAddr.String() 相同形态。
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


def _root_disk_total() -> int:
    try:
        # Unix 与 macOS 下 "/" 是稳定根分区；Windows 上也可作为当前盘符兜底。
        return shutil.disk_usage("/").total
    except OSError:
        # 容器或权限异常不应影响主进程启动。
        return 0


def _total_memory() -> int:
    if hasattr(os, "sysconf"):
        try:
            # POSIX 下通过页大小与物理页数估算总内存，不额外引入第三方依赖。
            page_size = os.sysconf("SC_PAGE_SIZE")
            pages = os.sysconf("SC_PHYS_PAGES")
            return int(page_size) * int(pages)
        except (OSError, ValueError):
            # 某些平台不支持这些 sysconf key，保持 0 兜底。
            return 0
    return 0
