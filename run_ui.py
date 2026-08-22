#!/usr/bin/env python3
"""
Точка входа для запуска PyQt-интерфейса BlocklistFW.
"""

import sys
import os
import logging

# ВРЕМЕННО ВКЛЮЧАЕМ ЛОГИРОВАНИЕ ДЛЯ ДИАГНОСТИКИ
# Только наши сообщения, без мусора от matplotlib и других библиотек
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
# Глушим ВСЁ, кроме нашего приложения
for logger_name in logging.root.manager.loggerDict:
    if not logger_name.startswith(("core.", "ui.", "services.", "__main__")):
        logging.getLogger(logger_name).setLevel(logging.CRITICAL)
logging.getLogger("win32com").setLevel(logging.CRITICAL)
logging.getLogger("PIL").setLevel(logging.CRITICAL)
logging.getLogger("PySide6").setLevel(logging.CRITICAL)
logging.getLogger("matplotlib").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from admin_check import is_admin, elevate
import ctypes

if not is_admin():
    logging.error("Запуск без прав администратора. Автоматически запрашиваем повышение прав...")
    # Автоматически запрашиваем повышение прав без диалога
    elevate()
    # elevate() вызовет sys.exit(0) после попытки повышения
    # Если повышение не удалось (пользователь отказался от UAC), процесс завершится
    sys.exit(0)

from ui.main_window import main

if __name__ == "__main__":
    main()