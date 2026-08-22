"""
Модуль для проверки и повышения прав администратора в Windows.
"""
import sys
import ctypes
import subprocess
import logging

logger = logging.getLogger(__name__)

def is_admin() -> bool:
    """Проверяет, запущен ли процесс с правами администратора."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate():
    """Перезапускает текущий скрипт с правами администратора."""
    if not is_admin():
        # Получаем путь к интерпретатору и аргументы
        python_exe = sys.executable
        script = sys.argv[0]
        params = ' '.join([script] + sys.argv[1:])
        # Запускаем с runas
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", python_exe, params, None, 1
        )
        sys.exit(0)

if __name__ == "__main__":
    # Этот блок используется только для тестирования модуля
    # В продакшене сообщения не выводятся
    # print(f"Админ: {is_admin()}")
    if not is_admin():
        # print("Повышаем права...")
        elevate()
    else:
        # print("Уже администратор.")
        pass