"""
Модуль Threat Intelligence для блокировки IP-адресов и доменов из публичных и пользовательских списков угроз.
"""

import sqlite3
import logging
import csv
import json
import gzip
import io
import re
import tarfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Dict, Any, Set, Tuple
import uuid
import ipaddress
import requests
from pathlib import Path

from core.engine import FirewallEngine
from core.rule import FirewallRule, RuleAction, RuleDirection, Protocol

logger = logging.getLogger(__name__)

# Компилируем regex для быстрой проверки IP/CIDR (используется в парсерах)
IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
CIDR_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')


class FeedFormat(Enum):
    """Формат источника угроз."""
    TXT = "txt"
    CSV = "csv"
    JSON = "json"


class ThreatType(Enum):
    """Тип угрозы."""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    SPAM = "spam"
    SCANNER = "scanner"
    C2 = "c2"
    UNKNOWN = "unknown"


@dataclass
class ThreatFeed:
    """Источник списка угроз."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    url: Optional[str] = None
    file_path: Optional[str] = None
    format: FeedFormat = FeedFormat.TXT
    update_interval: int = 86400  # секунды, по умолчанию сутки
    last_update: Optional[datetime] = None
    enabled: bool = True
    description: str = ""
    auth_type: str = "none"  # none, basic, api_key
    auth_data: Optional[Dict[str, str]] = None

    def is_local(self) -> bool:
        """Возвращает True, если источник — локальный файл."""
        return self.file_path is not None


@dataclass
class ThreatEntry:
    """Запись об угрозе (IP, домен)."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    feed_id: str = ""
    ip: Optional[str] = None
    cidr: Optional[str] = None
    domain: Optional[str] = None
    threat_type: ThreatType = ThreatType.UNKNOWN
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    resolved_ips: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_ips(self) -> List[str]:
        """Возвращает список IP-адресов, связанных с записью."""
        ips = []
        if self.ip:
            ips.append(self.ip)
        if self.cidr:
            ips.append(self.cidr)
        if self.resolved_ips:
            ips.extend(self.resolved_ips)
        return list(set(ips))


class ThreatIntelligenceManager:
    """Центральный менеджер модуля Threat Intelligence."""

    def __init__(self, db_path: str = "threat_intelligence.db"):
        self.db_path = Path(db_path)
        self.conn = None
        self.last_update_errors = {}  # {feed_id: error_message}
        self._init_db()

    def _init_db(self) -> None:
        """Инициализирует базу данных SQLite с необходимыми таблицами."""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        # Включаем WAL-режим для ускорения массовых вставок
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=OFF")
        cursor.execute("PRAGMA cache_size=-64000")  # 64MB кэш
        # Таблица источников
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feeds (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT,
                file_path TEXT,
                format TEXT NOT NULL,
                update_interval INTEGER DEFAULT 86400,
                last_update TIMESTAMP,
                enabled BOOLEAN DEFAULT 1,
                description TEXT,
                auth_type TEXT DEFAULT 'none',
                auth_data TEXT
            )
        """)
        # Таблица записей угроз
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_entries (
                id TEXT PRIMARY KEY,
                feed_id TEXT NOT NULL,
                ip TEXT,
                cidr TEXT,
                domain TEXT,
                threat_type TEXT NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                resolved_ips TEXT,
                metadata TEXT,
                FOREIGN KEY (feed_id) REFERENCES feeds (id) ON DELETE CASCADE
            )
        """)
        # Индекс для быстрого поиска по feed_id
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_threat_entries_feed_id
            ON threat_entries (feed_id)
        """)
        # Таблица правил блокировки
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS block_rules (
                id TEXT PRIMARY KEY,
                threat_entry_id TEXT NOT NULL,
                firewall_rule_id TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                active BOOLEAN DEFAULT 1,
                FOREIGN KEY (threat_entry_id) REFERENCES threat_entries (id) ON DELETE CASCADE
            )
        """)
        self.conn.commit()
        logger.info(f"База данных Threat Intelligence инициализирована: {self.db_path}")
        # Добавление предустановленных источников, если таблица пуста
        self._add_default_feeds()

    def _add_default_feeds(self) -> None:
        """Добавляет предустановленные источники угроз, если таблица пуста."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM feeds")
        count = cursor.fetchone()[0]
        if count > 0:
            logger.debug("Таблица источников не пуста, пропускаем добавление предустановленных.")
            return

        default_feeds = [
            ThreatFeed(
                name="CINS Army List",
                url="https://cinsarmy.com/list/ci-badguys.txt",
                format=FeedFormat.TXT,
                description="Список подозрительных IP-адресов от CINS Army"
            ),
            ThreatFeed(
                name="ET Block List",
                url="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                format=FeedFormat.TXT,
                description="Список блокируемых IP от Emerging Threats"
            )
        ]
        for feed in default_feeds:
            self.add_feed(feed)
            logger.info(f"Добавлен предустановленный источник: {feed.name}")

    def add_feed(self, feed: ThreatFeed) -> str:
        """Добавляет источник угроз в БД."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO feeds (id, name, url, file_path, format, update_interval,
                               last_update, enabled, description, auth_type, auth_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            feed.id, feed.name, feed.url, feed.file_path, feed.format.value,
            feed.update_interval, feed.last_update.isoformat() if feed.last_update else None,
            feed.enabled, feed.description, feed.auth_type,
            feed.auth_data if feed.auth_data is None else str(feed.auth_data)
        ))
        self.conn.commit()
        logger.info(f"Добавлен источник угроз: {feed.name} (ID: {feed.id})")
        return feed.id

    def get_feeds(self, enabled_only: bool = True) -> List[ThreatFeed]:
        """Возвращает список источников."""
        cursor = self.conn.cursor()
        query = "SELECT * FROM feeds"
        if enabled_only:
            query += " WHERE enabled = 1"
        cursor.execute(query)
        rows = cursor.fetchall()
        feeds = []
        for row in rows:
            feed = ThreatFeed(
                id=row[0],
                name=row[1],
                url=row[2],
                file_path=row[3],
                format=FeedFormat(row[4]),
                update_interval=row[5],
                last_update=datetime.fromisoformat(row[6]) if row[6] else None,
                enabled=bool(row[7]),
                description=row[8],
                auth_type=row[9],
                auth_data=eval(row[10]) if row[10] else None
            )
            feeds.append(feed)
        return feeds

    def get_feed_by_id(self, feed_id: str) -> Optional[ThreatFeed]:
        """Возвращает источник по ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return ThreatFeed(
            id=row[0],
            name=row[1],
            url=row[2],
            file_path=row[3],
            format=FeedFormat(row[4]),
            update_interval=row[5],
            last_update=datetime.fromisoformat(row[6]) if row[6] else None,
            enabled=bool(row[7]),
            description=row[8],
            auth_type=row[9],
            auth_data=eval(row[10]) if row[10] else None
        )

    def update_feed(self, feed: ThreatFeed) -> bool:
        """Обновляет источник угроз."""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE feeds SET
                name = ?, url = ?, file_path = ?, format = ?, update_interval = ?,
                last_update = ?, enabled = ?, description = ?, auth_type = ?, auth_data = ?
            WHERE id = ?
        """, (
            feed.name, feed.url, feed.file_path, feed.format.value,
            feed.update_interval,
            feed.last_update.isoformat() if feed.last_update else None,
            feed.enabled, feed.description, feed.auth_type,
            feed.auth_data if feed.auth_data is None else str(feed.auth_data),
            feed.id
        ))
        self.conn.commit()
        logger.info(f"Обновлён источник угроз: {feed.name}")
        return cursor.rowcount > 0

    def delete_feed(self, feed_id: str) -> bool:
        """Удаляет источник и все его записи."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
        self.conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"Удалён источник угроз ID: {feed_id}")
        return deleted

    def set_feed_last_update(self, feed_id: str, timestamp: datetime = None):
        """Устанавливает время последнего обновления источника."""
        if timestamp is None:
            timestamp = datetime.now()
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE feeds SET last_update = ? WHERE id = ?",
            (timestamp.isoformat(), feed_id)
        )
        self.conn.commit()

    def add_entry(self, entry: ThreatEntry) -> str:
        """Добавляет запись об угрозе в БД."""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO threat_entries (id, feed_id, ip, cidr, domain, threat_type,
                                        first_seen, last_seen, resolved_ips, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.id, entry.feed_id, entry.ip, entry.cidr, entry.domain,
            entry.threat_type.value, entry.first_seen.isoformat(),
            entry.last_seen.isoformat(), str(entry.resolved_ips), str(entry.metadata)
        ))
        self.conn.commit()
        logger.debug(f"Добавлена запись угрозы: {entry.ip or entry.domain}")
        return entry.id

    def add_entries_batch(self, entries: List[ThreatEntry]) -> int:
        """
        Добавляет записи угроз батчем (быстрая вставка).
        Возвращает количество добавленных записей.
        """
        if not entries:
            logger.info("add_entries_batch: entries пуст, возвращаем 0")
            return 0
        logger.info(f"add_entries_batch: начинаем вставку {len(entries)} записей")
        cursor = self.conn.cursor()
        data = []
        for entry in entries:
            data.append((
                entry.id, entry.feed_id, entry.ip, entry.cidr, entry.domain,
                entry.threat_type.value, entry.first_seen.isoformat(),
                entry.last_seen.isoformat(), str(entry.resolved_ips), str(entry.metadata)
            ))
        cursor.executemany("""
            INSERT INTO threat_entries (id, feed_id, ip, cidr, domain, threat_type,
                                        first_seen, last_seen, resolved_ips, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, data)
        self.conn.commit()
        logger.debug(f"Добавлено {len(data)} записей угроз батчем")
        return len(data)

    def get_entries(self, feed_id: Optional[str] = None) -> List[ThreatEntry]:
        """Возвращает записи угроз, опционально фильтруя по источнику."""
        cursor = self.conn.cursor()
        query = "SELECT * FROM threat_entries"
        params = []
        if feed_id:
            query += " WHERE feed_id = ?"
            params.append(feed_id)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        entries = []
        for row in rows:
            entry = ThreatEntry(
                id=row[0],
                feed_id=row[1],
                ip=row[2],
                cidr=row[3],
                domain=row[4],
                threat_type=ThreatType(row[5]),
                first_seen=datetime.fromisoformat(row[6]),
                last_seen=datetime.fromisoformat(row[7]),
                resolved_ips=eval(row[8]) if row[8] else [],
                metadata=eval(row[9]) if row[9] else {}
            )
            entries.append(entry)
        return entries

    def check_ip(self, ip: str) -> Optional[ThreatEntry]:
        """Проверяет, находится ли IP в списках угроз."""
        cursor = self.conn.cursor()
        # Проверка точного совпадения IP
        cursor.execute("SELECT * FROM threat_entries WHERE ip = ?", (ip,))
        row = cursor.fetchone()
        if row:
            return self._row_to_entry(row)
        # Проверка CIDR
        cursor.execute("SELECT * FROM threat_entries WHERE cidr IS NOT NULL")
        rows = cursor.fetchall()
        for row in rows:
            cidr = row[3]
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                    return self._row_to_entry(row)
            except ValueError:
                continue
        return None

    def _row_to_entry(self, row) -> ThreatEntry:
        """Преобразует строку БД в объект ThreatEntry."""
        return ThreatEntry(
            id=row[0],
            feed_id=row[1],
            ip=row[2],
            cidr=row[3],
            domain=row[4],
            threat_type=ThreatType(row[5]),
            first_seen=datetime.fromisoformat(row[6]),
            last_seen=datetime.fromisoformat(row[7]),
            resolved_ips=eval(row[8]) if row[8] else [],
            metadata=eval(row[9]) if row[9] else {}
        )

    def get_stale_feeds(self) -> List[ThreatFeed]:
        """Возвращает источники, требующие обновления."""
        feeds = self.get_feeds(enabled_only=True)
        stale = []
        now = datetime.now()
        for feed in feeds:
            if feed.last_update is None:
                stale.append(feed)
                continue
            delta = now - feed.last_update
            if delta.total_seconds() >= feed.update_interval:
                stale.append(feed)
        return stale

    def update_feed_entries(self, feed: ThreatFeed, entries: List[ThreatEntry]) -> int:
        """
        Обновляет записи для источника (удаляет старые, добавляет новые).
        Использует batch-вставку для ускорения.
        """
        logger.info(f"update_feed_entries: {feed.name}, получено {len(entries)} entries")
        cursor = self.conn.cursor()
        # Удаляем старые записи этого источника
        cursor.execute("DELETE FROM threat_entries WHERE feed_id = ?", (feed.id,))
        deleted_old = cursor.rowcount
        logger.info(f"update_feed_entries: удалено старых записей: {deleted_old}")
        # Дедупликация: убираем дубли внутри одного обновления
        seen = set()
        unique_entries = []
        for entry in entries:
            key = (entry.ip, entry.cidr, entry.domain)
            if key in seen:
                continue
            seen.add(key)
            unique_entries.append(entry)
        logger.info(f"update_feed_entries: после дедупликации: {len(unique_entries)}")
        # Добавляем уникальные записи батчем
        added = self.add_entries_batch(unique_entries)
        self.set_feed_last_update(feed.id)
        logger.info(
            f"Обновлён источник {feed.name}: добавлено {added} записей "
            f"(было {len(entries)}, уникальных {len(unique_entries)})"
        )
        return added

    def update_stale_feeds(self) -> Dict[str, int]:
        """Обновляет все источники, требующие обновления."""
        stale = self.get_stale_feeds()
        loader = ThreatFeedLoader(self)
        results = {}
        for feed in stale:
            try:
                entries = loader.load_feed(feed)
                added = self.update_feed_entries(feed, entries)
                results[feed.id] = added
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Ошибка обновления источника {feed.name}: {error_msg}")
                results[feed.id] = -1
                self.last_update_errors[feed.id] = error_msg
        return results

    def update_all_feeds(self, progress_callback=None) -> Dict[str, int]:
        """
        Принудительно обновляет все включённые источники.

        Аргументы:
            progress_callback: Опциональный callback с сигнатурой (current_index, total, feed_name).
                Вызывается перед обработкой каждого источника.

        Возвращает:
            Словарь {feed_id: количество добавленных записей или -1 при ошибке}.
        """
        feeds = self.get_feeds(enabled_only=True)
        logger.info(f"update_all_feeds: получено {len(feeds)} включённых источников")
        for f in feeds:
            logger.info(f"  - {f.name}: id={f.id}, format={f.format}, url={f.url}")
        loader = ThreatFeedLoader(self)
        results = {}
        self.last_update_errors.clear()  # очищаем предыдущие ошибки
        total = len(feeds)
        for i, feed in enumerate(feeds):
            if progress_callback:
                progress_callback(i, total, feed.name)
            try:
                entries = loader.load_feed(feed)
                logger.info(f"update_all_feeds: {feed.name} -> load_feed вернул {len(entries)} entries")
                added = self.update_feed_entries(feed, entries)
                logger.info(f"update_all_feeds: {feed.name} -> update_feed_entries вернул {added}")
                results[feed.id] = added
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Ошибка обновления источника {feed.name}: {error_msg}")
                results[feed.id] = -1
                self.last_update_errors[feed.id] = error_msg
        if progress_callback:
            progress_callback(total, total, "")
        logger.info(f"update_all_feeds: результаты: {results}")
        return results

    def close(self):
        """Закрывает соединение с БД."""
        if self.conn:
            self.conn.close()
            logger.info("Соединение с БД Threat Intelligence закрыто.")

    def get_last_update_errors(self) -> Dict[str, str]:
        """Возвращает словарь с ошибками последнего обновления источников."""
        return self.last_update_errors.copy()

    def delete_all_block_rules(self) -> int:
        """
        Удаляет все записи из таблицы block_rules (правила блокировки угроз).
        Также удаляет все записи угроз (threat_entries), что каскадно удалит block_rules.
        Возвращает количество удалённых записей угроз.
        """
        cursor = self.conn.cursor()
        # Сначала удаляем все записи угроз (каскадно удалит block_rules)
        cursor.execute("DELETE FROM threat_entries")
        deleted_entries = cursor.rowcount
        # Также явно удаляем из block_rules на случай, если каскад не сработал
        cursor.execute("DELETE FROM block_rules")
        deleted_rules = cursor.rowcount
        self.conn.commit()
        total_deleted = deleted_entries + deleted_rules
        logger.info(f"Удалено {deleted_entries} записей угроз и {deleted_rules} записей правил блокировки угроз.")
        return total_deleted


class ThreatFeedLoader:
    """Загрузчик данных из источников."""

    def __init__(self, manager: ThreatIntelligenceManager):
        self.manager = manager
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        # Настройка повторных попыток и keep-alive
        retry_adapter = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=10,
            pool_maxsize=20
        )
        self.session.mount('http://', retry_adapter)
        self.session.mount('https://', retry_adapter)

    def load_feed(self, feed: ThreatFeed) -> List[ThreatEntry]:
        """Загружает и парсит данные из источника."""
        logger.info(f"load_feed: {feed.name}, format={feed.format}, url={feed.url}")
        if feed.is_local():
            content = self._load_from_file(feed.file_path)
        else:
            content = self._load_from_url(feed.url, feed.auth_type, feed.auth_data)
        logger.info(f"load_feed: content length={len(content)} chars, first 100 chars={content[:100]!r}")
        # Парсинг в зависимости от формата
        if feed.format == FeedFormat.TXT:
            entries = self._parse_txt(content, feed.id)
            logger.info(f"load_feed: _parse_txt вернул {len(entries)} entries")
            return entries
        elif feed.format == FeedFormat.CSV:
            entries = self._parse_csv(content, feed.id)
            logger.info(f"load_feed: _parse_csv вернул {len(entries)} entries")
            return entries
        elif feed.format == FeedFormat.JSON:
            entries = self._parse_json(content, feed.id)
            logger.info(f"load_feed: _parse_json вернул {len(entries)} entries")
            return entries
        else:
            logger.warning(f"Неизвестный формат {feed.format}, пропускаем.")
            return []

    def _load_from_file(self, file_path: str) -> str:
        """Загружает содержимое из локального файла (поддерживает .gz, .tar.gz, .tgz, .tar)."""
        try:
            raw_data = None
            path_lower = file_path.lower()

            # Пробуем распаковать как tar.gz / tgz / tar
            if path_lower.endswith('.tar.gz') or path_lower.endswith('.tgz'):
                with tarfile.open(file_path, 'r:gz') as tar:
                    raw_data = self._extract_text_from_tar(tar, file_path)
            elif path_lower.endswith('.tar'):
                with tarfile.open(file_path, 'r:') as tar:
                    raw_data = self._extract_text_from_tar(tar, file_path)
            elif path_lower.endswith('.gz'):
                with gzip.open(file_path, 'rb') as f:
                    raw_data = f.read()
            else:
                with open(file_path, 'rb') as f:
                    raw_data = f.read()

            if raw_data is None:
                raise ValueError(f"Не удалось прочитать данные из {file_path}")

            # Пробуем декодировать как UTF-8, с fallback на другие кодировки
            try:
                return raw_data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return raw_data.decode('latin-1')
                except UnicodeDecodeError:
                    return raw_data.decode('cp1252', errors='replace')

        except Exception as e:
            logger.error(f"Ошибка чтения файла {file_path}: {e}")
            raise

    def _load_from_url(self, url: str, auth_type: str, auth_data: Optional[Dict]) -> str:
        """
        Загружает содержимое по URL.
        Поддерживает: gzip, tar.gz, tgz, tar, plain text.
        Определяет формат архива по:
        1. Расширению конечного URL (после редиректов)
        2. Magic bytes gzip (\\x1f\\x8b) для любых URL
        """
        try:
            response = self._do_request(url, auth_type, auth_data)
            raw_content = response.content
            # Используем конечный URL (после редиректов) для определения расширения
            effective_url = response.url
            logger.info(f"_load_from_url: получено {len(raw_content)} bytes raw, url={url}, effective_url={effective_url}")

            # Определяем формат архива по расширению конечного URL
            url_lower = effective_url.lower()

            # Пробуем распаковать как tar.gz / tgz
            if url_lower.endswith('.tar.gz') or url_lower.endswith('.tgz'):
                try:
                    with tarfile.open(fileobj=io.BytesIO(raw_content), mode='r:gz') as tar:
                        text = self._extract_text_from_tar(tar, effective_url)
                        if text:
                            logger.info(f"_load_from_url: tar.gz распакован, {len(text)} bytes")
                            return text
                except (tarfile.TarError, EOFError) as e:
                    logger.warning(f"Ошибка распаковки tar.gz для {effective_url}: {e}")

            # Пробуем распаковать как tar
            if url_lower.endswith('.tar'):
                try:
                    with tarfile.open(fileobj=io.BytesIO(raw_content), mode='r:') as tar:
                        text = self._extract_text_from_tar(tar, effective_url)
                        if text:
                            logger.info(f"_load_from_url: tar распакован, {len(text)} bytes")
                            return text
                except (tarfile.TarError, EOFError) as e:
                    logger.warning(f"Ошибка распаковки tar для {effective_url}: {e}")

            # Пробуем распаковать как gzip:
            # 1. Если URL (конечный) заканчивается на .gz
            # 2. Если контент начинается с gzip magic bytes (\\x1f\\x8b) — для URL через редиректы/сокращалки
            should_try_gzip = url_lower.endswith('.gz') or raw_content[:2] == b'\x1f\x8b'
            if should_try_gzip:
                try:
                    raw_content = gzip.decompress(raw_content)
                    logger.info(f"_load_from_url: gzip распакован, теперь {len(raw_content)} bytes")
                except Exception as e:
                    logger.warning(f"Ошибка распаковки gzip для {effective_url}: {e}")

            # Пробуем декодировать как UTF-8, с fallback на другие кодировки
            try:
                text = raw_content.decode('utf-8')
                logger.info(f"_load_from_url: декодирован utf-8, {len(text)} chars")
                return text
            except UnicodeDecodeError:
                try:
                    text = raw_content.decode('latin-1')
                    logger.info(f"_load_from_url: декодирован latin-1, {len(text)} chars")
                    return text
                except UnicodeDecodeError:
                    text = raw_content.decode('cp1252', errors='replace')
                    logger.info(f"_load_from_url: декодирован cp1252, {len(text)} chars")
                    return text

        except Exception as e:
            logger.error(f"Ошибка загрузки URL {url}: {e}")
            raise

    def _do_request(self, url: str, auth_type: str, auth_data: Optional[Dict]) -> requests.Response:
        """
        Выполняет HTTP-запрос с поддержкой SSL fallback и retry.
        """
        last_exception = None

        for attempt in range(3):
            try:
                kwargs = {
                    'timeout': 120,
                    'verify': True,
                }
                if auth_type == 'basic':
                    kwargs['auth'] = (auth_data.get('username'), auth_data.get('password'))
                elif auth_type == 'api_key':
                    kwargs['headers'] = {'Authorization': f"Bearer {auth_data.get('api_key')}"}

                response = self.session.get(url, **kwargs)
                response.raise_for_status()
                return response

            except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as e:
                last_exception = e
                if attempt == 0:
                    # При SSL/соединения ошибке пробуем без верификации
                    logger.warning(f"SSL/Connection error for {url} (attempt {attempt + 1}), retrying without verification: {e}")
                    try:
                        kwargs = {
                            'timeout': 120,
                            'verify': False,
                        }
                        if auth_type == 'basic':
                            kwargs['auth'] = (auth_data.get('username'), auth_data.get('password'))
                        elif auth_type == 'api_key':
                            kwargs['headers'] = {'Authorization': f"Bearer {auth_data.get('api_key')}"}

                        # Подавляем предупреждение об SSL
                        import urllib3
                        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

                        response = self.session.get(url, **kwargs)
                        response.raise_for_status()
                        return response
                    except Exception as e2:
                        last_exception = e2
                        logger.warning(f"SSL fallback also failed for {url} (attempt {attempt + 1}): {e2}")
                else:
                    logger.warning(f"Request failed for {url} (attempt {attempt + 1}): {e}")

            except requests.exceptions.Timeout as e:
                last_exception = e
                logger.warning(f"Timeout for {url} (attempt {attempt + 1}): {e}")

            except requests.exceptions.RequestException as e:
                last_exception = e
                logger.warning(f"Request failed for {url} (attempt {attempt + 1}): {e}")

            # Экспоненциальная задержка между попытками
            if attempt < 2:
                time.sleep(1 * (2 ** attempt))

        raise last_exception or RuntimeError(f"Не удалось загрузить {url} после 3 попыток")

    @staticmethod
    def _extract_text_from_tar(tar: tarfile.TarFile, source_name: str) -> Optional[bytes]:
        """
        Извлекает текстовое содержимое из tar-архива.
        Ищет первый текстовый файл (.txt, .csv, .json) или любой файл маленького размера.
        """
        for member in tar.getmembers():
            if not member.isfile():
                continue
            # Ищем текстовые файлы по расширению
            name_lower = member.name.lower()
            if any(name_lower.endswith(ext) for ext in ('.txt', '.csv', '.json', '.dat', '.list', '.ipset')):
                try:
                    data = tar.extractfile(member)
                    if data:
                        return data.read()
                except Exception as e:
                    logger.warning(f"Ошибка извлечения {member.name} из {source_name}: {e}")
                    continue

        # Если текстовых файлов не найдено, берём первый небольшой файл
        for member in tar.getmembers():
            if member.isfile() and member.size < 10 * 1024 * 1024:  # < 10MB
                try:
                    data = tar.extractfile(member)
                    if data:
                        logger.info(f"Извлечён первый доступный файл {member.name} из {source_name}")
                        return data.read()
                except Exception:
                    continue

        raise ValueError(f"Не удалось найти текстовый файл в архиве {source_name}")

    def _parse_txt(self, content: str, feed_id: str) -> List[ThreatEntry]:
        """
        Парсит текстовый файл с IP-адресами и CIDR (построчно).
        Оптимизирован: использует regex для быстрой предварительной фильтрации.
        """
        entries = []
        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Удаляем комментарии в конце строки
            if '#' in line:
                line = line.split('#')[0].strip()
                if not line:
                    continue
            # Берём первый токен
            parts = line.split()
            if not parts:
                continue
            token = parts[0]
            # Также можно разбить по запятой, точке с запятой
            for sep in (',', ';', '|'):
                if sep in token:
                    token = token.split(sep)[0]
            token = token.strip()
            if not token:
                continue

            # Быстрая проверка через regex (на порядки быстрее ipaddress)
            if CIDR_RE.match(token):
                try:
                    ipaddress.ip_network(token, strict=False)
                    entries.append(ThreatEntry(feed_id=feed_id, cidr=token))
                    continue
                except ValueError:
                    pass
            elif IP_RE.match(token):
                try:
                    ipaddress.ip_address(token)
                    entries.append(ThreatEntry(feed_id=feed_id, ip=token))
                    continue
                except ValueError:
                    pass
            else:
                # Не IP и не CIDR, возможно домен или другая строка
                logger.debug(f"Пропущена строка, не являющаяся IP/CIDR: {line} (токен: {token})")
        return entries

    def _parse_csv(self, content: str, feed_id: str) -> List[ThreatEntry]:
        """Парсит CSV файл с колонками ip, domain, threat_type, first_seen, last_seen."""
        entries = []
        try:
            reader = csv.reader(content.splitlines())
            headers = next(reader, None)
            if headers is None:
                logger.warning("CSV файл пуст")
                return []
            # Нормализуем заголовки: убираем пробелы, приводим к нижнему регистру
            headers = [h.strip().lower() for h in headers]
            # Определяем индексы нужных колонок
            ip_idx = domain_idx = threat_type_idx = first_seen_idx = last_seen_idx = -1
            for i, h in enumerate(headers):
                if h in ('ip', 'address', 'ip_address'):
                    ip_idx = i
                elif h in ('domain', 'hostname', 'host'):
                    domain_idx = i
                elif h in ('threat_type', 'type', 'category'):
                    threat_type_idx = i
                elif h in ('first_seen', 'firstseen', 'first seen'):
                    first_seen_idx = i
                elif h in ('last_seen', 'lastseen', 'last seen'):
                    last_seen_idx = i
            # Обрабатываем строки
            for row in reader:
                if not row:
                    continue
                ip = row[ip_idx].strip() if ip_idx >= 0 and ip_idx < len(row) else None
                domain = row[domain_idx].strip() if domain_idx >= 0 and domain_idx < len(row) else None
                threat_type_str = row[threat_type_idx].strip() if threat_type_idx >= 0 and threat_type_idx < len(row) else None
                first_seen_str = row[first_seen_idx].strip() if first_seen_idx >= 0 and first_seen_idx < len(row) else None
                last_seen_str = row[last_seen_idx].strip() if last_seen_idx >= 0 and last_seen_idx < len(row) else None
                # Если нет ни IP, ни домена - пропускаем
                if not ip and not domain:
                    continue
                # Определяем тип угрозы
                threat_type = ThreatType.UNKNOWN
                if threat_type_str:
                    try:
                        threat_type = ThreatType(threat_type_str.lower())
                    except ValueError:
                        for tt in ThreatType:
                            if tt.value in threat_type_str.lower():
                                threat_type = tt
                                break
                # Парсим даты
                first_seen = datetime.now()
                last_seen = datetime.now()
                if first_seen_str:
                    try:
                        first_seen = datetime.fromisoformat(first_seen_str)
                    except ValueError:
                        pass
                if last_seen_str:
                    try:
                        last_seen = datetime.fromisoformat(last_seen_str)
                    except ValueError:
                        pass
                # Создаём запись
                entry = ThreatEntry(
                    feed_id=feed_id,
                    ip=ip if ip else None,
                    domain=domain if domain else None,
                    threat_type=threat_type,
                    first_seen=first_seen,
                    last_seen=last_seen
                )
                entries.append(entry)
        except Exception as e:
            logger.error(f"Ошибка парсинга CSV: {e}")
        logger.info(f"CSV парсинг завершён, найдено {len(entries)} записей")
        return entries

    def _parse_json(self, content: str, feed_id: str) -> List[ThreatEntry]:
        """Парсит JSON файл (поддерживает Abuse.ch и подобные форматы)."""
        entries = []
        try:
            data = json.loads(content)
            # Если data - список строк (IP/доменов)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        line = item.strip()
                        if not line:
                            continue
                        entry = self._parse_line_as_ip_or_cidr(line, feed_id)
                        if entry:
                            entries.append(entry)
                        else:
                            entry = ThreatEntry(feed_id=feed_id, domain=line)
                            entries.append(entry)
                    elif isinstance(item, dict):
                        entry = self._parse_json_object(item, feed_id)
                        if entry:
                            entries.append(entry)
            # Если data - словарь с ключами, содержащими списки
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, str):
                                entry = self._parse_line_as_ip_or_cidr(item, feed_id)
                                if entry:
                                    entries.append(entry)
                                else:
                                    entries.append(ThreatEntry(feed_id=feed_id, domain=item))
                            elif isinstance(item, dict):
                                entry = self._parse_json_object(item, feed_id)
                                if entry:
                                    entries.append(entry)
                    elif isinstance(value, dict):
                        entry = self._parse_json_object(value, feed_id)
                        if entry:
                            entries.append(entry)
            else:
                logger.warning(f"Неизвестная структура JSON: {type(data)}")
        except json.JSONDecodeError as e:
            logger.error(f"Ошибка декодирования JSON: {e}")
        except Exception as e:
            logger.error(f"Ошибка парсинга JSON: {e}")
        logger.info(f"JSON парсинг завершён, найдено {len(entries)} записей")
        return entries

    def _parse_line_as_ip_or_cidr(self, line: str, feed_id: str) -> Optional[ThreatEntry]:
        """Пытается разобрать строку как IP или CIDR, возвращает ThreatEntry или None."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        if '#' in line:
            line = line.split('#')[0].strip()
            if not line:
                return None

        # Быстрая проверка через regex
        if CIDR_RE.match(line):
            try:
                ipaddress.ip_network(line, strict=False)
                return ThreatEntry(feed_id=feed_id, cidr=line)
            except ValueError:
                pass
        elif IP_RE.match(line):
            try:
                ipaddress.ip_address(line)
                return ThreatEntry(feed_id=feed_id, ip=line)
            except ValueError:
                pass
        return None

    def _parse_json_object(self, obj: Dict, feed_id: str) -> Optional[ThreatEntry]:
        """Парсит объект JSON в ThreatEntry."""
        ip = obj.get('ip') or obj.get('address')
        domain = obj.get('domain') or obj.get('hostname')
        threat_type_str = obj.get('threat_type') or obj.get('type') or obj.get('category')
        first_seen_str = obj.get('first_seen') or obj.get('firstSeen')
        last_seen_str = obj.get('last_seen') or obj.get('lastSeen')
        # Если нет ни IP, ни домена - пропускаем
        if not ip and not domain:
            return None
        threat_type = ThreatType.UNKNOWN
        if threat_type_str:
            try:
                threat_type = ThreatType(threat_type_str.lower())
            except ValueError:
                for tt in ThreatType:
                    if tt.value in str(threat_type_str).lower():
                        threat_type = tt
                        break
        first_seen = datetime.now()
        last_seen = datetime.now()
        if first_seen_str:
            try:
                first_seen = datetime.fromisoformat(first_seen_str)
            except ValueError:
                pass
        if last_seen_str:
            try:
                last_seen = datetime.fromisoformat(last_seen_str)
            except ValueError:
                pass
        return ThreatEntry(
            feed_id=feed_id,
            ip=ip,
            domain=domain,
            threat_type=threat_type,
            first_seen=first_seen,
            last_seen=last_seen,
            metadata=obj  # сохраняем исходный объект как метаданные
        )


class DomainResolver:
    """Резолвер доменов с кэшированием."""

    def __init__(self, cache_ttl: int = 3600):
        self.cache: Dict[str, Tuple[List[str], datetime]] = {}
        self.cache_ttl = cache_ttl

    def resolve(self, domain: str) -> List[str]:
        """Разрешает домен в список IP-адресов."""
        now = datetime.now()
        if domain in self.cache:
            ips, timestamp = self.cache[domain]
            if (now - timestamp).total_seconds() < self.cache_ttl:
                return ips
        try:
            import socket
            ips = socket.gethostbyname_ex(domain)[2]
            self.cache[domain] = (ips, now)
            logger.debug(f"Разрешён домен {domain} -> {ips}")
            return ips
        except socket.gaierror as e:
            logger.warning(f"Не удалось разрешить домен {domain}: {e}")
            return []

    def clear_cache(self):
        """Очищает кэш."""
        self.cache.clear()


class ThreatRuleGenerator:
    """Генератор правил фаервола на основе записей угроз."""

    def __init__(self, engine: FirewallEngine, domain_resolver: Optional[DomainResolver] = None):
        self.engine = engine
        self.domain_resolver = domain_resolver

    def generate_rule(self, entry: ThreatEntry, feed: ThreatFeed, direction: RuleDirection = RuleDirection.INBOUND) -> FirewallRule:
        """Создаёт правило блокировки для записи угрозы с указанным направлением."""
        from core.rule import RuleAction, RuleDirection, Protocol
        remote_addresses = []
        # Если есть IP или CIDR, добавляем их
        if entry.ip:
            remote_addresses.append(entry.ip)
        if entry.cidr:
            remote_addresses.append(entry.cidr)
        # Если есть домен, резолвим его в IP-адреса
        if entry.domain:
            if self.domain_resolver:
                try:
                    ips = self.domain_resolver.resolve(entry.domain)
                    if ips:
                        remote_addresses.extend(ips)
                        entry.resolved_ips = ips
                    else:
                        logger.warning(f"Не удалось разрешить домен {entry.domain}")
                except Exception as e:
                    logger.error(f"Ошибка резолвинга домена {entry.domain}: {e}")
            else:
                logger.warning(f"Домен {entry.domain} не может быть разрешён (отсутствует DomainResolver)")
        # Если после резолвинга есть resolved_ips, добавляем их тоже
        if entry.resolved_ips:
            remote_addresses.extend(ip for ip in entry.resolved_ips if ip not in remote_addresses)
        # Убираем дубликаты
        remote_addresses = list(set(remote_addresses))
        # Если нет адресов для блокировки, создаём правило с доменом (как fallback)
        if not remote_addresses and entry.domain:
            remote_addresses.append(entry.domain)
        base_name = f"ThreatIntel: {feed.name} - {entry.ip or entry.domain or entry.cidr}"
        # Добавляем суффикс направления для уникальности
        if direction == RuleDirection.INBOUND:
            name = f"{base_name} (Inbound)"
        else:
            name = f"{base_name} (Outbound)"
        rule = FirewallRule(
            name=name,
            action=RuleAction.BLOCK,
            direction=direction,
            protocol=Protocol.ANY,
            remote_addresses=remote_addresses,
            enabled=True
        )
        return rule

    def apply_entry(self,
                    entry: ThreatEntry,
                    feed: ThreatFeed,
                    existing_names: Optional[set] = None,
                    on_rule_added=None) -> Tuple[bool, int]:
        """Создаёт и добавляет два правила блокировки (входящее и исходящее).

        Возвращает кортеж (успех, количество пропущенных уже существовавших правил).
        """
        from core.rule import RuleDirection
        existing_names = existing_names if existing_names is not None else set()
        inbound_rule = self.generate_rule(entry, feed, RuleDirection.INBOUND)
        outbound_rule = self.generate_rule(entry, feed, RuleDirection.OUTBOUND)

        added = 0
        skipped_existing = 0
        for rule in (inbound_rule, outbound_rule):
            if rule.name in existing_names:
                skipped_existing += 1  # правило уже существует — не создаём дубль
                continue
            try:
                if self.engine.add_rule(rule):
                    existing_names.add(rule.name)
                    added += 1
                    if on_rule_added:
                        on_rule_added(rule.name)
                else:
                    skipped_existing += 1
            except Exception as e:
                logger.error(f"Ошибка добавления правила {rule.name}: {e}")
                skipped_existing += 1
        return added > 0, skipped_existing

    def generate_grouped_rules(self, entries: List[ThreatEntry], feed: ThreatFeed, max_addresses_per_rule: int = 200) -> List[FirewallRule]:
        """
        Создаёт группированные правила для списка записей угроз.
        Объединяет до max_addresses_per_rule IP-адресов в одном правиле для каждого направления.
        Адреса проходят валидацию, чтобы правила создавались корректно и удалялись стандартно.
        """
        import ipaddress as _ip
        from core.rule import RuleAction, RuleDirection, Protocol
        # Собираем все удалённые адреса из записей
        remote_addresses = []
        for entry in entries:
            if entry.ip:
                remote_addresses.append(entry.ip)
            if entry.cidr:
                remote_addresses.append(entry.cidr)
            if entry.resolved_ips:
                remote_addresses.extend(ip for ip in entry.resolved_ips if ip not in remote_addresses)

        # Убираем дубликаты и оставляем только корректные IP/CIDR
        unique = set()
        for addr in remote_addresses:
            addr = addr.strip()
            if not addr:
                continue
            try:
                if "/" in addr:
                    _ip.ip_network(addr, strict=False)
                else:
                    _ip.ip_address(addr)
                unique.add(addr)
            except ValueError:
                logger.debug(f"Пропускаем некорректный адрес при группировке: {addr!r}")
        remote_addresses = list(unique)
        if not remote_addresses:
            logger.warning("Нет IP-адресов для группировки")
            return []

        # Разбиваем на группы по max_addresses_per_rule
        grouped_rules = []
        for i in range(0, len(remote_addresses), max_addresses_per_rule):
            chunk = remote_addresses[i:i + max_addresses_per_rule]
            # Создаём правило для входящего трафика
            inbound_rule = FirewallRule(
                name=f"ThreatIntel: {feed.name} - Group Inbound {i//max_addresses_per_rule + 1}",
                action=RuleAction.BLOCK,
                direction=RuleDirection.INBOUND,
                protocol=Protocol.ANY,
                remote_addresses=chunk,
                enabled=True
            )
            # Создаём правило для исходящего трафика
            outbound_rule = FirewallRule(
                name=f"ThreatIntel: {feed.name} - Group Outbound {i//max_addresses_per_rule + 1}",
                action=RuleAction.BLOCK,
                direction=RuleDirection.OUTBOUND,
                protocol=Protocol.ANY,
                remote_addresses=chunk,
                enabled=True
            )
            grouped_rules.append(inbound_rule)
            grouped_rules.append(outbound_rule)

        logger.info(f"Создано {len(grouped_rules)} группированных правил для {len(remote_addresses)} адресов")
        return grouped_rules

    def apply_grouped_rules(self,
                            entries: List[ThreatEntry],
                            feed: ThreatFeed,
                            existing_names: Optional[set] = None,
                            on_rule_added=None) -> Tuple[bool, int]:
        """
        Применяет группированные правила для списка записей угроз.

        Пропускает уже существующие правила (по имени), чтобы не создавать дубли.
        Возвращает кортеж (успех, количество пропущенных уже существовавших правил).
        """
        rules = self.generate_grouped_rules(entries, feed)
        if not rules:
            return False, 0
        existing_names = existing_names if existing_names is not None else set()
        success_count = 0
        skipped_existing = 0
        for rule in rules:
            if rule.name in existing_names:
                skipped_existing += 1  # правило уже существует — не создаём дубль
                continue
            try:
                if self.engine.add_rule(rule):
                    existing_names.add(rule.name)
                    success_count += 1
                    if on_rule_added:
                        on_rule_added(rule.name)
                else:
                    skipped_existing += 1
            except Exception as e:
                logger.error(f"Ошибка добавления правила {rule.name}: {e}")
                skipped_existing += 1
        logger.info(f"Успешно добавлено {success_count} из {len(rules)} группированных правил")
        return success_count > 0, skipped_existing


if __name__ == "__main__":
    # Пример использования
    manager = ThreatIntelligenceManager()
    feed = ThreatFeed(
        name="CINS Army List",
        url="http://cinsscore.com/list/ci-badguys.txt",
        format=FeedFormat.TXT
    )
    feed_id = manager.add_feed(feed)
    # print(f"Добавлен источник с ID: {feed_id}")
    manager.close()