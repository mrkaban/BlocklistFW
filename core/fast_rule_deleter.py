"""
Радикально быстрый удалитель правил Windows Firewall.
Использует низкоуровневые интерфейсы для удаления тысяч правил за минуты.
"""

import logging
import subprocess
import threading
import time
import winreg
import warnings
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

from .engine import WindowsFirewallEngine

logger = logging.getLogger(__name__)


class FastRuleDeleter:
    """
    Удалитель правил, использующий три альтернативных метода для максимальной скорости:
    1. Прямое редактирование реестра (самый быстрый, но рискованный)
    2. WMI с фильтрацией по имени (быстрее COM)
    3. PowerShell с фильтром (Get-NetFirewallRule -Name "Prefix*")
    
    Методы применяются в порядке приоритета, с fallback на стандартный движок.
    """
    
    def __init__(self, engine: Optional[WindowsFirewallEngine] = None):
        """
        Инициализация удалителя.
        
        Аргументы:
            engine: Экземпляр WindowsFirewallEngine для запасного варианта.
        """
        self.engine = engine or WindowsFirewallEngine()
        self._registry_path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    
    def delete_by_prefix(self, prefix: str, method: str = "auto") -> Dict[str, int]:
        """
        Удаляет все правила, имена которых начинаются с заданного префикса.
        
        Аргументы:
            prefix: Префикс имён правил (например, "ThreatIntel: greensnow")
            method: Способ удаления ("registry", "wmi", "powershell", "com", "auto")
        
        Возвращает:
            Словарь со статистикой: {'total_found': X, 'deleted': Y, 'errors': Z, 'method_used': str}
        """
        logger.info(f"Начинаем удаление правил с префиксом '{prefix}' методом {method}")
        
        # Проверка прав администратора
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        if not is_admin:
            logger.warning("Отсутствуют права администратора. Удаление может быть невозможно или ограничено.")
        
        if method != "auto":
            # Прямой выбранный метод без fallback
            if method == "registry":
                return self._delete_by_prefix_registry(prefix)
            elif method == "wmi":
                return self._delete_by_prefix_wmi(prefix)
            elif method == "powershell":
                return self._delete_by_prefix_powershell(prefix)
            elif method == "com":
                return self._delete_by_prefix_com(prefix)
            else:
                raise ValueError(f"Неизвестный метод: {method}")
        
        # Автоматический выбор с fallback
        # Если нет прав администратора, реестр, WMI и PowerShell недоступны
        methods_order = [
            ("registry", self._is_registry_available() and is_admin),
            ("wmi", WMI_AVAILABLE and is_admin),
            ("powershell", is_admin),  # PowerShell требует прав администратора
            ("com", True)          # COM всегда доступен (предположительно)
        ]
        
        last_result = None
        last_method = None
        
        for method_name, available in methods_order:
            if not available:
                logger.info(f"Метод {method_name} недоступен, пропускаем")
                continue
                
            logger.info(f"Пробуем метод {method_name}")
            try:
                if method_name == "registry":
                    result = self._delete_by_prefix_registry(prefix)
                elif method_name == "wmi":
                    result = self._delete_by_prefix_wmi(prefix)
                elif method_name == "powershell":
                    result = self._delete_by_prefix_powershell(prefix)
                else:  # com
                    result = self._delete_by_prefix_com(prefix)
            except Exception as e:
                logger.error(f"Метод {method_name} вызвал исключение: {e}")
                result = {'total_found': 0, 'deleted': 0, 'errors': 1, 'method_used': method_name}
            
            last_result = result
            last_method = method_name
            
            # Проверяем, можно ли считать результат успешным
            total_found = result.get('total_found', 0)
            deleted = result.get('deleted', 0)
            errors = result.get('errors', 0)
            
            # Успех: удалены все найденные правила (deleted == total_found) или правил не найдено
            if total_found == 0 and errors == 0:
                logger.info(f"Метод {method_name}: правил не найдено, считаем успехом")
                return result
            if deleted > 0 and errors == 0:
                logger.info(f"Метод {method_name}: успешно удалено {deleted} правил")
                return result
            if deleted > 0 and errors < total_found:
                logger.info(f"Метод {method_name}: удалено {deleted} из {total_found}, ошибок {errors}")
                return result
            
            # Неудача: переходим к следующему методу
            logger.warning(f"Метод {method_name} не справился: найдено {total_found}, удалено {deleted}, ошибок {errors}")
        
        # Если дошли сюда, все методы провалились
        if last_result is not None:
            return last_result
        else:
            # Крайний случай, не должен произойти
            return {'total_found': 0, 'deleted': 0, 'errors': 1, 'method_used': 'none'}
    
    def _is_registry_available(self) -> bool:
        """Проверяет доступность реестра для записи."""
        try:
            # Пробуем открыть с правами на чтение и запись
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self._registry_path,
                                 0, winreg.KEY_READ | winreg.KEY_WRITE)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logger.warning(f"Реестр недоступен для записи: {e}")
            return False
    
    def _delete_by_prefix_registry(self, prefix: str) -> Dict[str, int]:
        """
        Удаляет правила через прямое редактирование реестра.
        Поддерживает различные форматы записей реестра Windows Firewall.
        Возвращает количество удалённых правил.
        """
        deleted = 0
        errors = 0
        total_found = 0

        try:
            # Открываем ключ с правами на чтение и запись
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self._registry_path,
                                 0, winreg.KEY_READ | winreg.KEY_WRITE)

            # Собираем имена значений для удаления
            to_delete = []
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    # В значении реестра содержится строка с параметрами правила
                    # Формат: "v2.26|Action=Block|Active=TRUE|Dir=In|Name=<rule_name>|..."
                    # Ищем поле Name различными способами для совместимости

                    # Способ 1: "Name=ThreatIntel:..." (стандартный формат)
                    found = False
                    name_start = value.find("Name=")
                    if name_start != -1:
                        name_value = value[name_start + 5:]  # после "Name="
                        # Ищем конец имени (следующий '|' или конец строки)
                        pipe_pos = name_value.find('|')
                        if pipe_pos != -1:
                            name_value = name_value[:pipe_pos]
                        if name_value.startswith(prefix):
                            to_delete.append(name)
                            total_found += 1
                            found = True

                    # Способ 2: "Name = ThreatIntel:..." (с пробелами вокруг =)
                    if not found:
                        import re as re_module
                        name_match = re_module.search(r'Name\s*=\s*([^|]+)', value)
                        if name_match:
                            name_value = name_match.group(1).strip()
                            if name_value.startswith(prefix):
                                to_delete.append(name)
                                total_found += 1
                                found = True

                    # Способ 3: префикс встречается в любом месте значения
                    # (нужно для некорректно созданных правил, у которых поле Name отсутствует)
                    if not found and prefix in value:
                        to_delete.append(name)
                        total_found += 1
                        found = True

                    i += 1
                except OSError:
                    break

            logger.info(f"Найдено {total_found} правил с префиксом '{prefix}' в реестре")

            # Удаляем значения
            for name in to_delete:
                try:
                    winreg.DeleteValue(key, name)
                    deleted += 1
                except Exception as e:
                    logger.error(f"Ошибка удаления значения реестра '{name}': {e}")
                    errors += 1

            winreg.CloseKey(key)

            # После изменения реестра нужно обновить политику фаервола
            self._refresh_firewall_policy()

        except Exception as e:
            logger.error(f"Критическая ошибка при работе с реестром: {e}")
            errors += 1

        return {
            'total_found': total_found,
            'deleted': deleted,
            'errors': errors,
            'method_used': 'registry'
        }
    
    def _delete_by_prefix_wmi(self, prefix: str) -> Dict[str, int]:
        """
        Удаляет правила через WMI с фильтрацией по имени.
        """
        if not WMI_AVAILABLE:
            logger.warning("WMI недоступен, переключаемся на PowerShell")
            return self._delete_by_prefix_powershell(prefix)
        
        deleted = 0
        errors = 0
        total_found = 0
        
        try:
            # Подключаемся к пространству имён StandardCimv2
            conn = wmi.WMI(namespace="StandardCimv2")
            
            # Ищем правила с фильтром по имени
            # WQL поддерживает LIKE с подстановочным символом
            query = f"SELECT * FROM MSFT_NetFirewallRule WHERE Name LIKE '{prefix}%'"
            rules = conn.query(query)
            
            total_found = len(rules)
            logger.info(f"Найдено {total_found} правил с префиксом '{prefix}' через WMI")
            
            for rule in rules:
                try:
                    # Удаляем правило через метод Delete
                    rule.Delete()
                    deleted += 1
                except Exception as e:
                    logger.error(f"Ошибка удаления правила '{rule.Name}' через WMI: {e}")
                    errors += 1
            
        except Exception as e:
            logger.error(f"Ошибка WMI: {e}")
            errors += 1
        
        return {
            'total_found': total_found,
            'deleted': deleted,
            'errors': errors,
            'method_used': 'wmi'
        }
    
    def _delete_by_prefix_powershell(self, prefix: str) -> Dict[str, int]:
        """
        Удаляет правила через PowerShell с фильтром по DisplayName.
        Использует Get-NetFirewallRule -DisplayName 'Prefix*' | Remove-NetFirewallRule
        """
        deleted = 0
        errors = 0
        total_found = 0

        try:
            # Сначала подсчитываем количество правил с фильтром по DisplayName
            count_cmd = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"@(Get-NetFirewallRule -DisplayName '{prefix}*' -ErrorAction SilentlyContinue).Count"
            ]
            result = subprocess.run(count_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                try:
                    total_found = int(result.stdout.strip())
                except ValueError:
                    total_found = 0
            else:
                total_found = 0

            logger.info(f"Найдено {total_found} правил с префиксом '{prefix}' через PowerShell (DisplayName)")

            if total_found == 0:
                return {
                    'total_found': 0,
                    'deleted': 0,
                    'errors': 0,
                    'method_used': 'powershell'
                }

            # Удаляем все правила одной командой с прямым фильтром -DisplayName
            delete_cmd = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"Get-NetFirewallRule -DisplayName '{prefix}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue"
            ]

            start_time = time.time()
            result = subprocess.run(delete_cmd, capture_output=True, text=True, timeout=300)
            elapsed = time.time() - start_time

            if result.returncode == 0:
                deleted = total_found
                logger.info(f"Успешно удалено {deleted} правил за {elapsed:.1f} секунд")
            else:
                errors = total_found
                logger.error(f"Ошибка удаления через PowerShell: {result.stderr[:500]}")

        except subprocess.TimeoutExpired:
            logger.error("Таймаут удаления через PowerShell (5 минут)")
            errors = total_found
        except Exception as e:
            logger.error(f"Исключение при удалении через PowerShell: {e}")
            errors = total_found

        return {
            'total_found': total_found,
            'deleted': deleted,
            'errors': errors,
            'method_used': 'powershell'
        }
    
    def _delete_by_prefix_com(self, prefix: str) -> Dict[str, int]:
        """
        Удаляет правила через стандартный COM API (как в оригинальном движке).
        Используется как fallback. Правильно инициализирует COM в каждом потоке.
        """
        logger.info(f"Используем COM API для удаления правил с префиксом '{prefix}'")

        # Получаем все правила через движок
        try:
            all_rules = self.engine.list_rules()
        except Exception as e:
            logger.error(f"Ошибка получения списка правил: {e}")
            return {'total_found': 0, 'deleted': 0, 'errors': 1, 'method_used': 'com'}

        # Фильтруем по префиксу
        matching_rules = [rule for rule in all_rules if rule.name.startswith(prefix)]
        total_found = len(matching_rules)

        logger.info(f"Найдено {total_found} правил с префиксом '{prefix}' через COM")

        if total_found == 0:
            return {'total_found': 0, 'deleted': 0, 'errors': 0, 'method_used': 'com'}

        # Удаляем параллельно с правильной инициализацией COM в каждом потоке
        deleted = 0
        errors = 0
        lock = threading.Lock()

        def delete_rule_com(rule) -> bool:
            """Удаляет правило через COM с инициализацией COM в потоке."""
            import pythoncom
            pythoncom.CoInitialize()
            try:
                # Создаём свой экземпляр движка для каждого потока.
                # Передаём и внутренний Name (rule.id), и DisplayName (rule.name),
                # чтобы удаление работало и через PowerShell, и через COM.
                from .engine import WindowsFirewallEngine
                thread_engine = WindowsFirewallEngine()
                success = thread_engine.delete_rule(rule.id, display_name=rule.name)
                return success
            except Exception as e:
                logger.error(f"Ошибка удаления правила '{rule.name}' в потоке: {e}")
                return False
            finally:
                pythoncom.CoUninitialize()

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_rule = {
                executor.submit(delete_rule_com, rule): rule
                for rule in matching_rules
            }

            for future in as_completed(future_to_rule):
                rule = future_to_rule[future]
                try:
                    success = future.result(timeout=60)
                    if success:
                        with lock:
                            deleted += 1
                    else:
                        with lock:
                            errors += 1
                        logger.warning(f"Не удалось удалить правило '{rule.name}'")
                except Exception as e:
                    with lock:
                        errors += 1
                    logger.error(f"Исключение при удалении правила '{rule.name}': {e}")

        return {
            'total_found': total_found,
            'deleted': deleted,
            'errors': errors,
            'method_used': 'com'
        }
    
    def _refresh_firewall_policy(self):
        """
        Обновляет политику фаервола после изменений в реестре.
        Вызывает команду netsh advfirewall refresh.
        """
        try:
            subprocess.run(["netsh", "advfirewall", "refresh"], 
                          capture_output=True, timeout=10)
            logger.debug("Политика фаервола обновлена")
        except Exception as e:
            logger.warning(f"Не удалось обновить политику фаервола: {e}")
    
    def benchmark_methods(self, prefix: str) -> Dict[str, Dict]:
        """
        Тестирует все доступные методы и возвращает результаты для сравнения.
        """
        results = {}
        
        if self._is_registry_available():
            start = time.time()
            result = self._delete_by_prefix_registry(prefix)
            result['time_seconds'] = time.time() - start
            results['registry'] = result
        
        if WMI_AVAILABLE:
            start = time.time()
            result = self._delete_by_prefix_wmi(prefix)
            result['time_seconds'] = time.time() - start
            results['wmi'] = result
        
        start = time.time()
        result = self._delete_by_prefix_powershell(prefix)
        result['time_seconds'] = time.time() - start
        results['powershell'] = result
        
        start = time.time()
        result = self._delete_by_prefix_com(prefix)
        result['time_seconds'] = time.time() - start
        results['com'] = result
        
        return results