"""
Централизованный журнал событий фаервола.
"""
import logging
import json
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict


class EventLevel(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SECURITY = "SECURITY"


class EventType(Enum):
    RULE_ADDED = "RULE_ADDED"
    RULE_DELETED = "RULE_DELETED"
    RULE_UPDATED = "RULE_UPDATED"
    RULE_ENABLED = "RULE_ENABLED"
    RULE_DISABLED = "RULE_DISABLED"
    CONNECTION_BLOCKED = "CONNECTION_BLOCKED"
    CONNECTION_ALLOWED = "CONNECTION_ALLOWED"
    MONITOR_UPDATE = "MONITOR_UPDATE"
    SETTINGS_CHANGED = "SETTINGS_CHANGED"
    BACKUP_CREATED = "BACKUP_CREATED"
    BACKUP_RESTORE = "BACKUP_RESTORE"
    IMPORT_EXPORT = "IMPORT_EXPORT"
    ERROR = "ERROR"
    THREAT_FEED_ADDED = "THREAT_FEED_ADDED"
    THREAT_FEED_UPDATED = "THREAT_FEED_UPDATED"
    THREAT_FEED_DELETED = "THREAT_FEED_DELETED"
    THREAT_FEED_REFRESHED = "THREAT_FEED_REFRESHED"
    THREAT_ENTRY_BLOCKED = "THREAT_ENTRY_BLOCKED"
    THREAT_DOMAIN_RESOLVED = "THREAT_DOMAIN_RESOLVED"
    THREAT_AUTO_UPDATE = "THREAT_AUTO_UPDATE"


@dataclass
class LogEntry:
    """Запись в журнале событий."""
    timestamp: datetime
    level: EventLevel
    event_type: EventType
    message: str
    details: Optional[Dict[str, Any]] = None
    source: str = "firewall"

    def to_dict(self) -> Dict[str, Any]:
        """Преобразование в словарь для сериализации."""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        d['level'] = self.level.value
        d['event_type'] = self.event_type.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        """Создание из словаря."""
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        data['level'] = EventLevel(data['level'])
        data['event_type'] = EventType(data['event_type'])
        return cls(**data)


class EventLogger:
    """
    Управление журналом событий: запись, хранение, фильтрация.
    """
    def __init__(self, max_entries: int = 1000):
        self.max_entries = max_entries
        self.entries: List[LogEntry] = []
        self._setup_logging()

    def _setup_logging(self):
        """Настройка стандартного логгера Python."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.py_logger = logging.getLogger('firewall')

    def log(self,
            level: EventLevel,
            event_type: EventType,
            message: str,
            details: Optional[Dict[str, Any]] = None,
            source: str = "firewall"):
        """
        Добавить запись в журнал.
        """
        entry = LogEntry(
            timestamp=datetime.now(),
            level=level,
            event_type=event_type,
            message=message,
            details=details,
            source=source
        )
        self.entries.append(entry)
        # Ограничение размера журнала
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]

        # Также пишем в стандартный логгер Python
        log_method = {
            EventLevel.INFO: self.py_logger.info,
            EventLevel.WARNING: self.py_logger.warning,
            EventLevel.ERROR: self.py_logger.error,
            EventLevel.SECURITY: self.py_logger.warning
        }.get(level, self.py_logger.info)
        log_method(f"[{event_type.value}] {message}")

    def info(self, event_type: EventType, message: str, **kwargs):
        """Короткий метод для INFO."""
        self.log(EventLevel.INFO, event_type, message, kwargs)

    def warning(self, event_type: EventType, message: str, **kwargs):
        """Короткий метод для WARNING."""
        self.log(EventLevel.WARNING, event_type, message, kwargs)

    def error(self, event_type: EventType, message: str, **kwargs):
        """Короткий метод для ERROR."""
        self.log(EventLevel.ERROR, event_type, message, kwargs)

    def get_entries(self,
                    level: Optional[EventLevel] = None,
                    event_type: Optional[EventType] = None,
                    source: Optional[str] = None,
                    limit: int = 100) -> List[LogEntry]:
        """
        Получить записи журнала с фильтрацией.
        """
        filtered = self.entries
        if level:
            filtered = [e for e in filtered if e.level == level]
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]
        if source:
            filtered = [e for e in filtered if e.source == source]
        return filtered[-limit:]

    def clear(self):
        """Очистить журнал."""
        self.entries.clear()

    def save_to_file(self, filepath: str):
        """Сохранить журнал в JSON файл."""
        data = [entry.to_dict() for entry in self.entries]
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load_from_file(self, filepath: str):
        """Загрузить журнал из JSON файла."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.entries = [LogEntry.from_dict(item) for item in data]
        except (FileNotFoundError, json.JSONDecodeError):
            self.entries = []


# Глобальный экземпляр логгера для использования во всём приложении
logger = EventLogger()


if __name__ == "__main__":
    # Тест
    logger.info(EventType.RULE_ADDED, "Правило 'Block Chrome' добавлено", rule_name="Block Chrome")
    logger.warning(EventType.CONNECTION_BLOCKED, "Блокировка подключения к 1.2.3.4",
                   remote_ip="1.2.3.4", port=80)
    logger.error(EventType.ERROR, "Ошибка при добавлении правила", error="Access denied")

    for entry in logger.get_entries():
        # print(f"{entry.timestamp} [{entry.level.value}] {entry.message}")
        pass