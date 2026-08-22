"""
Менеджер конфигурации для сохранения настроек между сеансами.
Сохраняет настройки в JSON файл в папке %APPDATA%/BlocklistFW.
"""
import json
import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ConfigurationManager:
    """Управляет сохранением и загрузкой настроек приложения."""

    def __init__(self, app_name: str = "BlocklistFW"):
        """
        Аргументы:
            app_name: Имя приложения для создания подпапки в APPDATA.
        """
        self.app_name = app_name
        self.config_dir = self._get_config_dir()
        self.config_file = self.config_dir / "config.json"
        self.settings: Dict[str, Any] = {}
        self._ensure_config_dir()

    def _get_config_dir(self) -> Path:
        """Возвращает путь к директории конфигурации."""
        # В Windows используем %APPDATA%
        appdata = os.getenv('APPDATA')
        if appdata:
            return Path(appdata) / self.app_name
        # Запасной вариант: текущая директория
        return Path.cwd() / "config"

    def _ensure_config_dir(self) -> None:
        """Создаёт директорию конфигурации, если её нет."""
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Не удалось создать директорию конфигурации {self.config_dir}: {e}")
            raise

    def load(self) -> Dict[str, Any]:
        """Загружает настройки из файла."""
        default_settings = self._get_default_settings()
        if not self.config_file.exists():
            logger.info(f"Файл конфигурации не найден, используются настройки по умолчанию: {self.config_file}")
            self.settings = default_settings
            return self.settings.copy()

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
            # Объединяем с настройками по умолчанию (чтобы добавить новые поля)
            self.settings = {**default_settings, **loaded}
            logger.info(f"Настройки загружены из {self.config_file}")
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации из {self.config_file}: {e}")
            self.settings = default_settings
        return self.settings.copy()

    def save(self, settings: Optional[Dict[str, Any]] = None) -> bool:
        """
        Сохраняет настройки в файл.

        Аргументы:
            settings: Словарь настроек для сохранения. Если None, сохраняет текущие self.settings.

        Возвращает:
            True если успешно, иначе False.
        """
        if settings is not None:
            self.settings = settings
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
            logger.info(f"Настройки сохранены в {self.config_file}")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации в {self.config_file}: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Возвращает значение настройки по ключу."""
        return self.settings.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Устанавливает значение настройки."""
        self.settings[key] = value

    def _get_default_settings(self) -> Dict[str, Any]:
        """Возвращает настройки по умолчанию."""
        return {
            "auto_refresh_monitor": True,
            "auto_refresh_logs": True,
            "excluded_ips": [],  # исключённые IP/CIDR, не попадающие в блокировку угроз
            "active_protection": False,
            "window_geometry": None,  # можно сохранять размер и положение окна
            "last_backup_dir": "",
            "include_logs_in_backup": True,
            "overwrite_on_restore": False,
            "monitor_update_interval_seconds": 1,  # интервал обновления монитора (1-60 секунд)
        }

    def get_config_path(self) -> Path:
        """Возвращает путь к файлу конфигурации."""
        return self.config_file


if __name__ == "__main__":
    # Пример использования
    import sys
    logging.basicConfig(level=logging.DEBUG)
    cm = ConfigurationManager()
    cm.load()
    # print(f"Текущие настройки: {cm.settings}")
    cm.set("active_protection", True)
    cm.save()
    # print(f"Сохранено в {cm.get_config_path()}")