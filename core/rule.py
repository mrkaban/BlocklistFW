"""
Модель правила фаервола.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List
import uuid
from datetime import datetime


class RuleAction(Enum):
    """Действие правила."""
    ALLOW = "allow"
    BLOCK = "block"


class RuleDirection(Enum):
    """Направление трафика."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class Protocol(Enum):
    """Сетевой протокол."""
    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


@dataclass
class FirewallRule:
    """Представляет правило фаервола."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    enabled: bool = True
    action: RuleAction = RuleAction.ALLOW
    direction: RuleDirection = RuleDirection.INBOUND
    protocol: Protocol = Protocol.ANY
    local_ports: Optional[List[int]] = None
    remote_ports: Optional[List[int]] = None
    local_addresses: Optional[List[str]] = None
    remote_addresses: Optional[List[str]] = None
    application_path: Optional[str] = None
    service_name: Optional[str] = None
    interface_types: str = "All"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Преобразует правило в словарь для сериализации."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "action": self.action.value,
            "direction": self.direction.value,
            "protocol": self.protocol.value,
            "local_ports": self.local_ports,
            "remote_ports": self.remote_ports,
            "local_addresses": self.local_addresses,
            "remote_addresses": self.remote_addresses,
            "application_path": self.application_path,
            "service_name": self.service_name,
            "interface_types": self.interface_types,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FirewallRule":
        """Создаёт правило из словаря."""
        rule = cls()
        rule.id = data.get("id", str(uuid.uuid4()))
        rule.name = data.get("name", "")
        rule.description = data.get("description", "")
        rule.enabled = data.get("enabled", True)
        rule.action = RuleAction(data.get("action", "allow"))
        rule.direction = RuleDirection(data.get("direction", "inbound"))
        rule.protocol = Protocol(data.get("protocol", "any"))
        rule.local_ports = data.get("local_ports")
        rule.remote_ports = data.get("remote_ports")
        rule.local_addresses = data.get("local_addresses")
        rule.remote_addresses = data.get("remote_addresses")
        rule.application_path = data.get("application_path")
        rule.service_name = data.get("service_name")
        rule.interface_types = data.get("interface_types", "All")
        created_at = data.get("created_at")
        if created_at:
            rule.created_at = datetime.fromisoformat(created_at)
        updated_at = data.get("updated_at")
        if updated_at:
            rule.updated_at = datetime.fromisoformat(updated_at)
        return rule

    def __str__(self) -> str:
        return f"{self.name} ({self.action.value} {self.direction.value})"