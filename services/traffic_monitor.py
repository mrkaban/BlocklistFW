"""
Мониторинг сетевого трафика через Windows API и psutil.
"""

import ctypes
from ctypes import wintypes
import psutil
import socket
from dataclasses import dataclass
from typing import List, Optional, Dict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class NetworkConnection:
    """Информация о сетевом подключении."""
    pid: int
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    protocol: str
    process_name: str
    timestamp: datetime


class TrafficMonitor:
    """Сборщик информации о сетевых подключениях."""

    # Константы Windows API
    AF_INET = 2  # IPv4
    TCP_TABLE_OWNER_PID_ALL = 5
    UDP_TABLE_OWNER_PID = 1

    def __init__(self):
        self._iphlpapi = ctypes.windll.iphlpapi
        self._process_cache: Dict[int, str] = {}  # pid -> имя процесса

    def get_all_connections(self) -> List[NetworkConnection]:
        """
        Возвращает список всех активных сетевых подключений (TCP + UDP).
        """
        connections = []
        connections.extend(self._get_tcp_connections())
        connections.extend(self._get_udp_connections())
        return connections

    def _get_tcp_connections(self) -> List[NetworkConnection]:
        """Получение TCP-подключений."""
        try:
            # Первый вызов для определения размера буфера
            size = wintypes.DWORD(0)
            self._iphlpapi.GetExtendedTcpTable(
                None, ctypes.byref(size), False,
                self.AF_INET, self.TCP_TABLE_OWNER_PID_ALL, 0
            )
            if size.value == 0:
                return []

            # Выделение буфера
            buffer = ctypes.create_string_buffer(size.value)
            ret = self._iphlpapi.GetExtendedTcpTable(
                buffer, ctypes.byref(size), False,
                self.AF_INET, self.TCP_TABLE_OWNER_PID_ALL, 0
            )
            if ret != 0:
                logger.warning(f"GetExtendedTcpTable failed with error {ret}")
                return []

            # Парсинг структуры MIB_TCPTABLE_OWNER_PID
            class MIB_TCPROW_OWNER_PID(ctypes.Structure):
                _fields_ = [
                    ("state", wintypes.DWORD),
                    ("local_addr", wintypes.DWORD),
                    ("local_port", wintypes.DWORD),
                    ("remote_addr", wintypes.DWORD),
                    ("remote_port", wintypes.DWORD),
                    ("pid", wintypes.DWORD),
                ]

            class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
                _fields_ = [
                    ("num_entries", wintypes.DWORD),
                    ("table", MIB_TCPROW_OWNER_PID * 0)
                ]

            table = ctypes.cast(buffer, ctypes.POINTER(MIB_TCPTABLE_OWNER_PID)).contents
            rows = ctypes.cast(
                table.table,
                ctypes.POINTER(MIB_TCPROW_OWNER_PID * table.num_entries)
            ).contents

            connections = []
            for row in rows:
                local_addr = self._int_to_ip(row.local_addr)
                remote_addr = self._int_to_ip(row.remote_addr)
                local_port = self._int_to_port(row.local_port)
                remote_port = self._int_to_port(row.remote_port)
                state = self._tcp_state_to_str(row.state)
                pid = row.pid
                process_name = self._get_process_name(pid)

                connections.append(NetworkConnection(
                    pid=pid,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    protocol="TCP",
                    process_name=process_name,
                    timestamp=datetime.now()
                ))
            return connections
        except Exception as e:
            logger.error(f"Error getting TCP connections: {e}")
            return []

    def _get_udp_connections(self) -> List[NetworkConnection]:
        """Получение UDP-подключений."""
        try:
            size = wintypes.DWORD(0)
            self._iphlpapi.GetExtendedUdpTable(
                None, ctypes.byref(size), False,
                self.AF_INET, self.UDP_TABLE_OWNER_PID, 0
            )
            if size.value == 0:
                return []

            buffer = ctypes.create_string_buffer(size.value)
            ret = self._iphlpapi.GetExtendedUdpTable(
                buffer, ctypes.byref(size), False,
                self.AF_INET, self.UDP_TABLE_OWNER_PID, 0
            )
            if ret != 0:
                logger.warning(f"GetExtendedUdpTable failed with error {ret}")
                return []

            class MIB_UDPROW_OWNER_PID(ctypes.Structure):
                _fields_ = [
                    ("local_addr", wintypes.DWORD),
                    ("local_port", wintypes.DWORD),
                    ("pid", wintypes.DWORD),
                ]

            class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
                _fields_ = [
                    ("num_entries", wintypes.DWORD),
                    ("table", MIB_UDPROW_OWNER_PID * 0)
                ]

            table = ctypes.cast(buffer, ctypes.POINTER(MIB_UDPTABLE_OWNER_PID)).contents
            rows = ctypes.cast(
                table.table,
                ctypes.POINTER(MIB_UDPROW_OWNER_PID * table.num_entries)
            ).contents

            connections = []
            for row in rows:
                local_addr = self._int_to_ip(row.local_addr)
                local_port = self._int_to_port(row.local_port)
                pid = row.pid
                process_name = self._get_process_name(pid)

                connections.append(NetworkConnection(
                    pid=pid,
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr="",
                    remote_port=0,
                    state="LISTEN",
                    protocol="UDP",
                    process_name=process_name,
                    timestamp=datetime.now()
                ))
            return connections
        except Exception as e:
            logger.error(f"Error getting UDP connections: {e}")
            return []

    def _int_to_ip(self, ip_int: int) -> str:
        """Преобразование целого числа в строку IP-адреса."""
        try:
            return socket.inet_ntoa(ctypes.c_uint32(ip_int))
        except:
            return "0.0.0.0"

    def _int_to_port(self, port_int: int) -> int:
        """Преобразование сетевого порядка байт порта в int."""
        return (port_int >> 8) | ((port_int & 0xFF) << 8)

    def _tcp_state_to_str(self, state: int) -> str:
        """Преобразование кода состояния TCP в строку."""
        states = {
            1: "CLOSED",
            2: "LISTEN",
            3: "SYN_SENT",
            4: "SYN_RECEIVED",
            5: "ESTABLISHED",
            6: "FIN_WAIT1",
            7: "FIN_WAIT2",
            8: "CLOSE_WAIT",
            9: "CLOSING",
            10: "LAST_ACK",
            11: "TIME_WAIT",
            12: "DELETE_TCB"
        }
        return states.get(state, f"UNKNOWN({state})")

    def _get_process_name(self, pid: int) -> str:
        """Получение имени процесса по PID с кэшированием."""
        if pid == 0:
            return "System"
        if pid in self._process_cache:
            return self._process_cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            self._process_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            self._process_cache[pid] = f"[PID {pid}]"
            return f"[PID {pid}]"

    def clear_cache(self):
        """Очистка кэша процессов."""
        self._process_cache.clear()


if __name__ == "__main__":
    # Тест монитора
    import sys
    logging.basicConfig(level=logging.INFO)
    monitor = TrafficMonitor()
    connections = monitor.get_all_connections()
    # печать(f"Найдено {len(connections)} подключений")
    for conn in connections[:5]:  # Показать первые 5
        # печать(f"{conn.protocol} {conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port} "
        #        f"state={conn.state} pid={conn.pid} ({conn.process_name})")
        pass