"""
Валидация правил фаервола.
"""

import ipaddress
from typing import List, Optional
from .rule import FirewallRule, Protocol


class RuleValidationError(Exception):
    """Исключение при валидации правила."""
    pass


def validate_rule(rule: FirewallRule) -> None:
    """
    Проверяет корректность правила.
    Выбрасывает RuleValidationError при ошибках.
    """
    if not rule.name.strip():
        raise RuleValidationError("Имя правила не может быть пустым")

    if rule.action is None:
        raise RuleValidationError("Действие правила не указано")

    if rule.direction is None:
        raise RuleValidationError("Направление правила не указано")

    if rule.protocol is None:
        raise RuleValidationError("Протокол не указан")

    # Проверка портов
    if rule.local_ports:
        _validate_ports(rule.local_ports, "локальные порты")
    if rule.remote_ports:
        _validate_ports(rule.remote_ports, "удалённые порты")

    # Проверка IP-адресов
    if rule.local_addresses:
        _validate_addresses(rule.local_addresses, "локальные адреса")
    if rule.remote_addresses:
        _validate_addresses(rule.remote_addresses, "удалённые адреса")

    # Проверка пути приложения
    if rule.application_path and not rule.application_path.strip():
        raise RuleValidationError("Путь к приложению не может быть пустым")

    # Проверка совместимости протокола и портов
    if rule.protocol == Protocol.ICMP and (rule.local_ports or rule.remote_ports):
        raise RuleValidationError("Для протокола ICMP порты не применяются")


def _validate_ports(ports: List[int], field_name: str) -> None:
    """Проверяет корректность списка портов."""
    for port in ports:
        if not (0 <= port <= 65535):
            raise RuleValidationError(
                f"Некорректный порт {port} в {field_name}. Допустимый диапазон: 0-65535"
            )


def _validate_addresses(addresses: List[str], field_name: str) -> None:
    """Проверяет корректность IP-адресов или подсетей."""
    for addr in addresses:
        if addr == "*":
            continue
        try:
            ipaddress.ip_network(addr, strict=False)
        except ValueError:
            raise RuleValidationError(
                f"Некорректный IP-адрес или подсеть '{addr}' в {field_name}"
            )