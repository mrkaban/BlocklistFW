"""
Воркер для фонового удаления правил фаервола.
Использует оптимизированный модуль FirewallRuleDeleter для быстрого удаления.
"""

import logging
import time
from typing import List, Tuple

from PySide6.QtCore import QThread, Signal

from core.engine import WindowsFirewallEngine
from core.rule_deleter import FirewallRuleDeleter

logger = logging.getLogger(__name__)


class DeleteRulesWorker(QThread):
    """Поток для удаления списка правил с отчётом о прогрессе."""
    
    # Сигналы
    progress = Signal(int, str)          # текущий прогресс, имя правила
    finished = Signal(int, int, list)    # успешно, ошибки, список неудачных правил
    error = Signal(str)                  # сообщение об ошибке
    
    def __init__(self, rule_ids: List[str], rule_names: List[str], parent=None):
        super().__init__(parent)
        if len(rule_ids) != len(rule_names):
            raise ValueError("Длины списков rule_ids и rule_names должны совпадать")
        self.rule_ids = rule_ids
        self.rule_names = rule_names
        # Движок и удалитель создаются внутри run() в потоке,
        # т.к. COM-объекты нельзя использовать из другого потока.
        self.engine = None
        self.deleter = None
        self._cancelled = False

    def cancel(self):
        """Запрос отмены операции."""
        self._cancelled = True

    def run(self):
        """Основной метод потока (с инициализацией COM в этом потоке)."""
        import pythoncom
        pythoncom.CoInitialize()
        try:
            # Создаём движок и удалитель в текущем потоке
            self.engine = WindowsFirewallEngine()
            self.deleter = FirewallRuleDeleter(self.engine)

            total = len(self.rule_ids)
            if total == 0:
                self.finished.emit(0, 0, [])
                return

            logger.info(f"Начинаем удаление {total} правил")

            # Для разного количества правил используем разные стратегии
            if total >= 100:
                result = self._delete_large_batch()
            elif total >= 10:
                result = self._delete_parallel()
            else:
                result = self._delete_single_with_progress()

            # Отправляем итоговый результат
            self.finished.emit(
                result['success_count'],
                result['error_count'],
                result['failed_rules']
            )
        except Exception as e:
            logger.exception(f"Ошибка воркера удаления: {e}")
            # Не даём потоку умереть молча — сообщаем об ошибке
            self.finished.emit(0, len(self.rule_ids), list(zip(self.rule_ids, self.rule_names)))
        finally:
            pythoncom.CoUninitialize()
    
    def _delete_large_batch(self) -> dict:
        """
        Удаляет большое количество правил (>=100) с использованием
        комбинированного подхода: пакетное удаление + параллельное.
        """
        total = len(self.rule_ids)
        success_count = 0
        error_count = 0
        failed_rules = []
        
        # Шаг 1: Пакетное удаление через PowerShell
        logger.info(f"Шаг 1: Пакетное удаление {total} правил")
        batch_result = self.deleter.delete_batch(self.rule_ids, batch_size=2000)
        
        success_count += batch_result['deleted']
        error_count += batch_result['errors']
        
        # Если есть ошибки, получаем оставшиеся правила
        if batch_result['errors'] > 0:
            remaining = self.deleter._get_remaining_rules(self.rule_ids)
            if remaining:
                logger.info(f"Шаг 2: Параллельное удаление {len(remaining)} оставшихся правил")
                
                # Создаём маппинг имён для прогресса
                remaining_with_names = [
                    (rule_id, self.rule_names[self.rule_ids.index(rule_id)])
                    for rule_id in remaining
                ]
                
                # Удаляем параллельно с прогрессом
                for i, (rule_id, rule_name) in enumerate(remaining_with_names, 1):
                    if self._cancelled:
                        break
                    
                    # Отправляем прогресс
                    current_progress = success_count + i
                    self.progress.emit(current_progress, rule_name)
                    
                    # Удаляем правило — передаём DisplayName (rule_name), чтобы COM fallback работал
                    success = self.deleter.delete_single(rule_name)
                    if success:
                        success_count += 1
                        error_count = max(0, error_count - 1)  # уменьшаем счётчик ошибок
                    else:
                        error_count += 1
                        failed_rules.append((rule_id, rule_name, "Не удалось удалить"))
                    
                    # Небольшая пауза для UI
                    self.msleep(10)
        
        return {
            'success_count': success_count,
            'error_count': error_count,
            'failed_rules': failed_rules
        }
    
    def _delete_parallel(self) -> dict:
        """
        Удаляет правила параллельно (10-99 правил).
        """
        total = len(self.rule_ids)
        success_count = 0
        error_count = 0
        failed_rules = []
        
        logger.info(f"Параллельное удаление {total} правил")
        
        # Используем параллельное удаление через deleter
        parallel_result = self.deleter.delete_parallel(self.rule_ids, max_workers=10)
        
        success_count = parallel_result['deleted']
        error_count = parallel_result['errors']
        
        # Для неудачных правил собираем информацию
        if error_count > 0:
            # Получаем оставшиеся правила
            remaining = self.deleter._get_remaining_rules(self.rule_ids)
            for rule_id in remaining:
                rule_name = self.rule_names[self.rule_ids.index(rule_id)]
                failed_rules.append((rule_id, rule_name, "Не удалось удалить параллельно"))
        
        # Отправляем прогресс для каждого правила
        for i, (rule_id, rule_name) in enumerate(zip(self.rule_ids, self.rule_names), 1):
            if self._cancelled:
                break
            self.progress.emit(i, rule_name)
            self.msleep(5)  # минимальная пауза для UI
        
        return {
            'success_count': success_count,
            'error_count': error_count,
            'failed_rules': failed_rules
        }
    
    def _delete_single_with_progress(self) -> dict:
        """
        Удаляет правила по одному с детальным прогрессом (<10 правил).
        """
        total = len(self.rule_ids)
        success_count = 0
        error_count = 0
        failed_rules = []
        
        logger.info(f"Последовательное удаление {total} правил")
        
        for i, (rule_id, rule_name) in enumerate(zip(self.rule_ids, self.rule_names), 1):
            if self._cancelled:
                break
            
            # Отправляем прогресс
            self.progress.emit(i, rule_name)
            
            # Удаляем правило — передаём DisplayName (rule_name), чтобы COM fallback работал
            success = self.deleter.delete_single(rule_name)
            if success:
                success_count += 1
            else:
                error_count += 1
                failed_rules.append((rule_id, rule_name, "Не удалось удалить"))
            
            # Небольшая пауза для UI
            self.msleep(20)
        
        return {
            'success_count': success_count,
            'error_count': error_count,
            'failed_rules': failed_rules
        }
    
    def _delete_single_rule(self, rule_id: str, rule_name: str) -> Tuple[bool, str]:
        """
        Удаляет одно правило через движок с таймаутом.
        Сохранён для обратной совместимости.
        """
        try:
            # Устанавливаем таймаут для удаления (максимум 35 секунд, чтобы покрыть PowerShell таймаут 30 сек)
            import threading
            result = [None]
            error_msg = [""]
            
            def delete_task():
                try:
                    if self._cancelled:
                        result[0] = False
                        error_msg[0] = "Отменено пользователем"
                        return
                    # Передаём rule_id (Name) для PowerShell и rule_name (DisplayName) для COM fallback
                    result[0] = self.engine.delete_rule(rule_id, display_name=rule_name)
                except Exception as e:
                    error_msg[0] = str(e)
                    result[0] = False
            
            thread = threading.Thread(target=delete_task)
            thread.daemon = True
            thread.start()
            thread.join(timeout=35)  # увеличенный таймаут
            
            if thread.is_alive():
                logger.warning(f"Таймаут удаления правила '{rule_name}' (35 секунд)")
                return False, "Таймаут 35 секунд"
            
            if result[0] is None:
                return False, "Неизвестная ошибка"
            
            if not result[0]:
                return False, error_msg[0] if error_msg[0] else "Не удалось удалить"
            return True, ""
        except Exception as e:
            logger.error(f"Исключение при удалении правила '{rule_name}': {e}")
            return False, str(e)


# Утилитарная функция для обратной совместимости
def create_delete_worker(rule_ids: List[str], rule_names: List[str]) -> DeleteRulesWorker:
    """
    Создаёт и возвращает экземпляр DeleteRulesWorker.
    
    Аргументы:
        rule_ids: Список идентификаторов правил.
        rule_names: Список имён правил.
        
    Возвращает:
        Экземпляр DeleteRulesWorker.
    """
    return DeleteRulesWorker(rule_ids, rule_names)