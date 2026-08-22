"""
Оптимизированный модуль для удаления правил фаервола.
Предоставляет методы для пакетного, параллельного и префиксного удаления.
"""

import logging
import subprocess
import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .engine import WindowsFirewallEngine

logger = logging.getLogger(__name__)


class FirewallRuleDeleter:
    """
    Оптимизированный удалитель правил фаервола.
    Использует комбинацию методов для максимальной скорости:
    1. Пакетное удаление через PowerShell (для больших объёмов)
    2. Параллельное удаление через COM API (для средних объёмов)
    """
    
    def __init__(self, engine: Optional[WindowsFirewallEngine] = None):
        """
        Инициализация удалителя.
        
        Аргументы:
            engine: Экземпляр WindowsFirewallEngine. Если None, создаётся новый.
        """
        self.engine = engine or WindowsFirewallEngine()
        
    def delete_single(self, rule_name: str) -> bool:
        """
        Удаляет одно правило.
        
        Аргументы:
            rule_name: Имя правила для удаления.
            
        Возвращает:
            True если правило удалено или не существует, False при ошибке.
        """
        try:
            return self.engine.delete_rule(rule_name)
        except Exception as e:
            logger.error(f"Ошибка удаления правила '{rule_name}': {e}")
            return False
    
    def delete_batch(self, rule_names: List[str], batch_size: int = 2000) -> Dict[str, int]:
        """
        Удаляет список правил пакетами через PowerShell.
        
        Аргументы:
            rule_names: Список имён правил для удаления.
            batch_size: Размер пакета (по умолчанию 2000).
            
        Возвращает:
            Словарь со статистикой: {'total': X, 'deleted': Y, 'errors': Z}
        """
        if not rule_names:
            return {'total': 0, 'deleted': 0, 'errors': 0, 'batches': 0}
        
        total = len(rule_names)
        deleted = 0
        errors = 0
        
        # Разбиваем на пакеты
        batches = [rule_names[i:i + batch_size] for i in range(0, total, batch_size)]
        logger.info(f"Начинаем пакетное удаление {total} правил, пакетов: {len(batches)}")
        
        for batch_idx, batch in enumerate(batches, 1):
            if self._delete_batch_via_powershell(batch):
                deleted += len(batch)
                logger.debug(f"Пакет {batch_idx}/{len(batches)} успешно удалён ({len(batch)} правил)")
            else:
                errors += len(batch)
                logger.warning(f"Пакет {batch_idx}/{len(batches)} не удалён ({len(batch)} правил)")
        
        # Проверяем оставшиеся правила и пытаемся удалить их по одному
        if errors > 0:
            # Получаем список оставшихся правил
            remaining = self._get_remaining_rules(rule_names)
            if remaining:
                logger.info(f"Пытаемся удалить {len(remaining)} оставшихся правил по одному")
                for rule_name in remaining:
                    if self.delete_single(rule_name):
                        deleted += 1
                        errors -= 1
                    else:
                        logger.warning(f"Не удалось удалить правило '{rule_name}' даже по одному")
        
        return {
            'total': total,
            'deleted': deleted,
            'errors': errors,
            'batches': len(batches)
        }
    
    def delete_parallel(self, rule_names: List[str], max_workers: int = 10) -> Dict[str, int]:
        """
        Удаляет правила параллельно через COM API.
        
        Аргументы:
            rule_names: Список имён правил для удаления.
            max_workers: Максимальное количество потоков.
            
        Возвращает:
            Словарь со статистикой.
        """
        if not rule_names:
            return {'total': 0, 'deleted': 0, 'errors': 0}
        
        total = len(rule_names)
        deleted = 0
        errors = 0
        
        logger.info(f"Начинаем параллельное удаление {total} правил, потоков: {max_workers}")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Создаём задачи
            future_to_name = {
                executor.submit(self.delete_single, name): name 
                for name in rule_names
            }
            
            # Обрабатываем результаты по мере завершения
            for future in as_completed(future_to_name):
                rule_name = future_to_name[future]
                try:
                    success = future.result(timeout=10)
                    if success:
                        deleted += 1
                    else:
                        errors += 1
                        logger.debug(f"Не удалось удалить правило '{rule_name}'")
                except Exception as e:
                    errors += 1
                    logger.error(f"Исключение при удалении правила '{rule_name}': {e}")
        
        return {
            'total': total,
            'deleted': deleted,
            'errors': errors,
            'workers': max_workers
        }
    
    def delete_by_prefix(self, prefix: str) -> Dict[str, int]:
        """
        Удаляет все правила, имена которых начинаются с указанного префикса.
        
        Аргументы:
            prefix: Префикс имён правил (например, "ThreatIntel:").
            
        Возвращает:
            Словарь со статистикой.
        """
        logger.info(f"Поиск правил с префиксом '{prefix}'")
        
        # Получаем все правила напрямую из движка (без кэша)
        rules = self.engine.list_rules()
        
        # Фильтруем по префиксу
        matching_rules = [rule for rule in rules if rule.name.startswith(prefix)]
        
        if not matching_rules:
            logger.info(f"Правил с префиксом '{prefix}' не найдено")
            return {'total': 0, 'deleted': 0, 'errors': 0, 'prefix': prefix}
        
        rule_names = [rule.name for rule in matching_rules]
        logger.info(f"Найдено {len(rule_names)} правил с префиксом '{prefix}'")
        
        # Для большого количества правил используем комбинированный подход
        if len(rule_names) > 1000:
            # Сначала пакетное удаление через PowerShell
            result = self.delete_batch(rule_names)
            # Затем параллельное удаление оставшихся
            if result['errors'] > 0:
                # Получаем оставшиеся правила
                remaining = self._get_remaining_rules(rule_names)
                if remaining:
                    logger.info(f"Пытаемся удалить {len(remaining)} оставшихся правил параллельно")
                    parallel_result = self.delete_parallel(remaining)
                    result['deleted'] += parallel_result['deleted']
                    result['errors'] = parallel_result['errors']
        else:
            # Для небольшого количества используем параллельное удаление
            result = self.delete_parallel(rule_names)
        
        result['prefix'] = prefix
        return result
    
    def delete_all_threat_intel(self) -> Dict[str, int]:
        """
        Удаляет все правила блокировки угроз (с префиксом "ThreatIntel:").
        
        Возвращает:
            Словарь со статистикой.
        """
        return self.delete_by_prefix("ThreatIntel:")
    
    def _delete_batch_via_powershell(self, rule_names: List[str]) -> bool:
        """
        Удаляет пакет правил через PowerShell.
        
        Аргументы:
            rule_names: Список имён правил для удаления.
            
        Возвращает:
            True если пакет обработан успешно, False при ошибке.
        """
        if not rule_names:
            return True
        
        # Экранируем кавычки в именах
        escaped_names = [name.replace("'", "''") for name in rule_names]
        names_str = "','".join(escaped_names)
        
        # PowerShell команда с полным подавлением вывода
        ps_command = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

$rules = @('{names_str}')
$deleted = 0

foreach ($rule in $rules) {{
    try {{
        Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $deleted++
    }} catch {{
        # Игнорируем ошибки, правило может уже не существовать
    }}
}}

# Возвращаем количество удалённых правил
$deleted
"""
        
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_command],
                capture_output=True,
                text=True,
                shell=False,
                timeout=300  # 5 минут на пакет
            )
            
            if result.returncode == 0:
                try:
                    deleted_count = int(result.stdout.strip())
                    logger.debug(f"PowerShell удалил {deleted_count} правил из {len(rule_names)}")
                    return deleted_count > 0 or len(rule_names) == 0
                except ValueError:
                    # Если не удалось распарсить вывод, считаем успехом если код возврата 0
                    return True
            else:
                logger.warning(f"PowerShell вернул код ошибки {result.returncode}: {result.stderr[:200]}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error(f"Таймаут при пакетном удалении {len(rule_names)} правил через PowerShell")
            return False
        except Exception as e:
            logger.error(f"Ошибка при пакетном удалении через PowerShell: {e}")
            return False
    
    def _get_remaining_rules(self, rule_names: List[str]) -> List[str]:
        """
        Возвращает список правил из переданного списка, которые всё ещё существуют.
        
        Аргументы:
            rule_names: Список имён правил для проверки.
            
        Возвращает:
            Список имён правил, которые всё ещё существуют.
        """
        try:
            existing_rules = self.engine.list_rules()
            existing_names = {rule.name for rule in existing_rules}
            return [name for name in rule_names if name in existing_names]
        except Exception as e:
            logger.error(f"Ошибка получения оставшихся правил: {e}")
            return rule_names  # В случае ошибки считаем, что все правила остались
    


# Утилитарные функции для обратной совместимости

def delete_rules_batch(rule_names: List[str], batch_size: int = 2000) -> Dict[str, int]:
    """
    Утилитарная функция для пакетного удаления правил.
    
    Аргументы:
        rule_names: Список имён правил.
        batch_size: Размер пакета.
        
    Возвращает:
        Словарь со статистикой.
    """
    deleter = FirewallRuleDeleter()
    return deleter.delete_batch(rule_names, batch_size)


def delete_rules_by_prefix(prefix: str) -> Dict[str, int]:
    """
    Утилитарная функция для удаления правил по префиксу.
    
    Аргументы:
        prefix: Префикс имён правил.
        
    Возвращает:
        Словарь со статистикой.
    """
    deleter = FirewallRuleDeleter()
    return deleter.delete_by_prefix(prefix)