"""
Модуль для резервного копирования и восстановления конфигурации фаервола.
"""

import zipfile
import json
import os
import shutil
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

from services.event_logger import EventLogger, EventType


class BackupManager:
    """Управление резервными копиями конфигурации."""

    def __init__(self, base_dir: str = "."):
        """
        :param base_dir: Базовый каталог проекта (где находятся файлы правил, настроек и логов).
        """
        self.base_dir = Path(base_dir)
        self.event_logger = EventLogger()

    def create_backup(self,
                      rules: Optional[List[Dict[str, Any]]] = None,
                      feeds: Optional[List[Dict[str, Any]]] = None,
                      entries: Optional[List[Dict[str, Any]]] = None,
                      include_logs: bool = True,
                      output_path: Optional[str] = None) -> str:
        """
        Создаёт ZIP-архив с резервной копией правил брандмауэра,
        списков URL-источников угроз и записей IP/доменов.

        :param rules: Список словарей правил (экспортированных из Windows Firewall).
        :param feeds: Список словарей источников угроз.
        :param entries: Список словарей записей IP/доменов.
        :param include_logs: Включать ли файл журнала событий в резервную копию.
        :param output_path: Полный путь к выходному ZIP-файлу. Если None, генерируется автоматически.
        :return: Путь к созданному архиву.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_path is None:
            output_path = str(self.base_dir / f"backup_firewall_{timestamp}.zip")

        manifest = {
            "version": 1,
            "created_at": timestamp,
            "rules": len(rules or []),
            "feeds": len(feeds or []),
            "entries": len(entries or []),
            "include_logs": include_logs,
        }

        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.writestr("backup_manifest.json",
                              json.dumps(manifest, indent=2, ensure_ascii=False))
                zipf.writestr("rules.json",
                              json.dumps(rules or [], indent=2, ensure_ascii=False))
                zipf.writestr("feeds.json",
                              json.dumps(feeds or [], indent=2, ensure_ascii=False))
                zipf.writestr("entries.json",
                              json.dumps(entries or [], indent=2, ensure_ascii=False))
                if include_logs:
                    logs_path = self.base_dir / "event_logs.json"
                    if logs_path.exists():
                        zipf.write(logs_path, "event_logs.json")

            self.event_logger.info(EventType.BACKUP_RESTORE,
                                   f"Резервная копия создана: {output_path}")
            return output_path
        except Exception as e:
            self.event_logger.error(EventType.BACKUP_RESTORE,
                                    f"Ошибка создания резервной копии: {e}")
            raise

    def restore_backup(self, backup_path: str) -> Dict[str, Any]:
        """
        Читает резервную копию и возвращает восстановленные данные.

        :param backup_path: Путь к архиву.
        :return: Словарь с ключами rules, feeds, entries (списки словарей).
        """
        backup_path = Path(backup_path)
        if not backup_path.exists():
            raise FileNotFoundError(f"Архив не найден: {backup_path}")

        result: Dict[str, Any] = {"rules": [], "feeds": [], "entries": []}
        try:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                file_list = zipf.namelist()
                # Читаем правила, источники и записи из JSON-файлов архива
                for key, fname in (("rules", "rules.json"),
                                   ("feeds", "feeds.json"),
                                   ("entries", "entries.json")):
                    if fname in file_list:
                        try:
                            result[key] = json.loads(zipf.read(fname).decode('utf-8'))
                        except Exception as e:
                            self.event_logger.error(
                                EventType.BACKUP_RESTORE,
                                f"Не удалось прочитать {fname}: {e}")

                # Восстанавливаем журнал событий, если он есть в архиве
                if "event_logs.json" in file_list:
                    zipf.extract("event_logs.json", self.base_dir)
                    result["logs_restored"] = True

            self.event_logger.info(
                EventType.BACKUP_RESTORE,
                f"Резервная копия {backup_path} прочитана: "
                f"{len(result['rules'])} правил, {len(result['feeds'])} источников, "
                f"{len(result['entries'])} записей.")
            return result
        except Exception as e:
            self.event_logger.error(EventType.BACKUP_RESTORE,
                                    f"Ошибка чтения резервной копии: {e}")
            raise

    def list_backups(self, pattern: str = "backup_firewall_*.zip") -> List[Path]:
        """
        Возвращает список файлов резервных копий в базовом каталоге.

        :param pattern: Шаблон поиска.
        :return: Список путей к архивам (отсортированный по дате создания, новые первые).
        """
        backups = list(self.base_dir.glob(pattern))
        # Сортировка по времени изменения (новые сверху)
        backups.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return backups

    def delete_backup(self, backup_path: str) -> bool:
        """
        Удаление резервной копии.

        :param backup_path: Путь к архиву.
        :return: True, если удаление успешно.
        """
        try:
            Path(backup_path).unlink()
            self.event_logger.info(EventType.BACKUP_RESTORE,
                                   f"Резервная копия удалена: {backup_path}")
            return True
        except Exception as e:
            self.event_logger.error(EventType.BACKUP_RESTORE,
                                    f"Ошибка удаления резервной копии: {e}")
            return False

    def _collect_extra_files(self) -> List[Path]:
        """
        Сбор дополнительных файлов для резервного копирования.

        :return: Список путей к файлам.
        """
        extra = []
        # Конфигурационные файлы в каталоге core/
        core_dir = self.base_dir / "core"
        if core_dir.exists():
            for ext in ("*.json", "*.yaml", "*.yml", "*.ini"):
                extra.extend(core_dir.glob(ext))
        # Конфигурационные файлы в каталоге services/
        services_dir = self.base_dir / "services"
        if services_dir.exists():
            for ext in ("*.json", "*.yaml", "*.yml", "*.ini"):
                extra.extend(services_dir.glob(ext))
        # Файл констант
        constants = self.base_dir / "constants.py"
        if constants.exists():
            extra.append(constants)
        # Файл адаптера
        adapter = self.base_dir / "adapter.py"
        if adapter.exists():
            extra.append(adapter)
        return extra