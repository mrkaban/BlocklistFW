"""
Движок фаервола и реализация для Windows Firewall.
"""

import abc
import logging
import subprocess
import time
from typing import List, Optional
from .rule import FirewallRule, RuleAction, RuleDirection, Protocol

logger = logging.getLogger(__name__)


class FirewallEngine(abc.ABC):
    """Абстрактный интерфейс движка фаервола."""

    @abc.abstractmethod
    def list_rules(self) -> List[FirewallRule]:
        """Возвращает список всех правил."""
        pass

    @abc.abstractmethod
    def add_rule(self, rule: FirewallRule) -> bool:
        """Добавляет новое правило."""
        pass

    @abc.abstractmethod
    def delete_rule(self, rule_id: str) -> bool:
        """Удаляет правило по идентификатору."""
        pass

    @abc.abstractmethod
    def update_rule(self, rule: FirewallRule) -> bool:
        """Обновляет существующее правило."""
        pass

    @abc.abstractmethod
    def enable_rule(self, rule_id: str) -> bool:
        """Включает правило."""
        pass

    @abc.abstractmethod
    def disable_rule(self, rule_id: str) -> bool:
        """Отключает правило."""
        pass

    @abc.abstractmethod
    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Возвращает правило по идентификатору."""
        pass


class WindowsFirewallEngine(FirewallEngine):
    """Реализация движка через Windows Firewall API (win32com)."""

    def __init__(self):
        try:
            import win32com.client
            import pythoncom
            self.win32com = win32com.client
            # CoInitialize для COM-операций
            pythoncom.CoInitialize()
            # Используем Dispatch — CoCreateInstance недоступен (CLSID не зарегистрирован).
            # Для свежих данных после удаления используется PowerShell (list_rules).
            self.fwPolicy2 = self.win32com.Dispatch("HNetCfg.FwPolicy2")
            logger.info("Windows Firewall engine initialized (FwPolicy2 via Dispatch)")
        except ImportError:
            logger.error("pywin32 not installed. Please install pywin32.")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Windows Firewall: {e}")
            raise

    def list_rules(self) -> List[FirewallRule]:
        """Возвращает список всех правил Windows Firewall.
        
        Сначала пытается получить данные через PowerShell (свежие данные,
        минуя COM-кэш). При ошибке — fallback на COM с _refresh_policy().
        """
        import time
        start_time = time.time()
        
        # Пробуем PowerShell
        rules = self._list_rules_powershell()
        if rules is not None:
            elapsed = time.time() - start_time
            logger.info(f"list_rules: {len(rules)} rules via PowerShell in {elapsed:.2f}s")
            return rules
        
        # Запасной вариант на COM
        logger.info("PowerShell list_rules недоступен, пробуем COM")
        rules = self._list_rules_com()
        elapsed = time.time() - start_time
        logger.info(f"list_rules: {len(rules)} rules via COM in {elapsed:.2f}s")
        return rules
    
    def _list_rules_powershell(self) -> Optional[List[FirewallRule]]:
        """Пытается получить правила через PowerShell.
        Возвращает список правил или None при ошибке.
        Использует ЧИСЛОВЫЕ значения для Action и Direction (не локализованные строки),
        чтобы корректно работать на любом языке Windows.
        
        Оптимизация: хэш-таблицы по InstanceID для PortFilter и AddressFilter (3 запроса всего),
        вместо pipeline для каждого правила (954 запроса для 477 правил).
        """
        ps_script = """
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

# ВАЖНО: принудительно устанавливаем UTF-8 для вывода, иначе на русской Windows
# Write-Output будет использовать CP1251, и ConvertTo-Json (UTF-8) будет повреждён.
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# 1. Получаем все правила
try {
    $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
} catch {
    Write-Output 'ERROR: Get-NetFirewallRule failed'
    exit 1
}

if (-not $rules) {
    Write-Output '[]'
    exit 0
}

# 2. Строим хэш-таблицы фильтров по InstanceID (3 запроса всего, а не 954)
# Это в 300+ раз быстрее, чем pipeline для каждого правила.
$portFilters = @{}
Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object {
    $portFilters[$_.InstanceID] = $_
}

$addressFilters = @{}
Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | ForEach-Object {
    $addressFilters[$_.InstanceID] = $_
}

# 3. Собираем результат
# ВАЖНО: используем ЧИСЛОВЫЕ значения для Action (0=Block,1=Allow) и Direction (1=Inbound,2=Outbound),
# чтобы избежать проблем с локализацией на разных языках Windows.
$result = @()
foreach ($rule in $rules) {
    $pf = $portFilters[$rule.InstanceID]
    $af = $addressFilters[$rule.InstanceID]
    
    $lp = if ($pf -and $pf.LocalPort -and $pf.LocalPort -ne '*') { $pf.LocalPort } else { $null }
    $rp = if ($pf -and $pf.RemotePort -and $pf.RemotePort -ne '*') { $pf.RemotePort } else { $null }
    $la = if ($af -and $af.LocalAddress -and $af.LocalAddress -ne '*') { $af.LocalAddress } else { $null }
    $ra = if ($af -and $af.RemoteAddress -and $af.RemoteAddress -ne '*') { $af.RemoteAddress } else { $null }
    
    # Protocol: числовые значения (6=TCP, 17=UDP, 1=ICMP) или строки (RPC, Teredo...)
    $proto = if ($pf) { $pf.Protocol } else { 'Any' }
    
    $result += [PSCustomObject]@{
        Name = $rule.Name
        DisplayName = $rule.DisplayName
        Description = $rule.Description
        Enabled = [bool]$rule.Enabled
        Action = [int]$rule.Action
        Direction = [int]$rule.Direction
        Protocol = $proto
        LocalPort = $lp
        RemotePort = $rp
        LocalAddress = $la
        RemoteAddress = $ra
        ApplicationName = $rule.ApplicationName
        InterfaceTypes = if ($rule.InterfaceTypes) { $rule.InterfaceTypes } else { 'All' }
    }
}

# 4. Сериализуем в JSON с Depth 2 (достаточно для плоских объектов)
$json = $result | ConvertTo-Json -Compress -Depth 2
Write-Output $json
"""
        try:
            # PowerShell выводит UTF-8, но text=True на русской Windows использует CP1251.
            # Читаем как байты и декодируем в UTF-8 вручную.
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                capture_output=True,
                timeout=120  # Увеличен с 30 до 120 для систем с большим количеством правил
            )
            # Декодируем stdout как UTF-8 (PowerShell ConvertTo-Json выводит UTF-8)
            stdout = result.stdout.decode('utf-8', errors='replace').strip()
            stderr_text = result.stderr.decode('utf-8', errors='replace')
            
            if result.returncode != 0:
                logger.warning(f"PowerShell list_rules error (rc={result.returncode}): {stderr_text[:300]}")
                return None
            if not stdout or stdout == '[]':
                logger.debug("PowerShell list_rules: пустой результат")
                return []
            
            import json
            data = json.loads(stdout)
            
            if isinstance(data, dict):
                data = [data]
            
            # DEBUG: логируем первые 3 правила для диагностики
            if data:
                for i, item in enumerate(data[:3]):
                    logger.debug(f"DEBUG RAW RULE {i}: Name={item.get('Name','?')}, DisplayName={item.get('DisplayName','?')}, "
                                 f"Action={item.get('Action','?')}, Direction={item.get('Direction','?')}, "
                                 f"Protocol={item.get('Protocol','?')}, LocalPort={item.get('LocalPort','?')}, "
                                 f"RemotePort={item.get('RemotePort','?')}, LocalAddress={item.get('LocalAddress','?')}, "
                                 f"RemoteAddress={item.get('RemoteAddress','?')}")
            
            rules = []
            for item in data:
                try:
                    rule = FirewallRule()
                    # Name = внутренний ID (GUID/путь) — используется для удаления через PowerShell
                    # DisplayName = человекочитаемое имя — используется для отображения и COM-операций
                    rule.id = item.get("Name", "") or ""
                    rule.name = item.get("DisplayName") or rule.id
                    rule.description = item.get("Description") or ""
                    rule.enabled = bool(item.get("Enabled", False))
                    
                    # Action: 0=Block, 1=Allow (числовые значения, не локализованные строки)
                    action_val = item.get("Action", 0)
                    if isinstance(action_val, int):
                        rule.action = RuleAction.ALLOW if action_val == 1 else RuleAction.BLOCK
                    else:
                        rule.action = RuleAction.ALLOW if str(action_val) == "Allow" else RuleAction.BLOCK
                    
                    # Direction: 1=Inbound, 2=Outbound (числовые значения, не локализованные строки)
                    dir_val = item.get("Direction", 1)
                    if isinstance(dir_val, int):
                        rule.direction = RuleDirection.INBOUND if dir_val == 1 else RuleDirection.OUTBOUND
                    else:
                        rule.direction = RuleDirection.INBOUND if str(dir_val) == "Inbound" else RuleDirection.OUTBOUND
                    
                    # Protocol: может быть числом (6=TCP, 17=UDP, 1=ICMP) или строкой (RPC, Teredo...)
                    proto_val = item.get("Protocol", "Any")
                    if isinstance(proto_val, int):
                        if proto_val == 6:
                            rule.protocol = Protocol.TCP
                        elif proto_val == 17:
                            rule.protocol = Protocol.UDP
                        elif proto_val == 1:
                            rule.protocol = Protocol.ICMP
                        else:
                            rule.protocol = Protocol.ANY
                    else:
                        proto_str = str(proto_val)
                        if proto_str == "TCP":
                            rule.protocol = Protocol.TCP
                        elif proto_str == "UDP":
                            rule.protocol = Protocol.UDP
                        elif proto_str in ("ICMPv4", "ICMPv6", "ICMP"):
                            rule.protocol = Protocol.ICMP
                        else:
                            # Любой другой протокол (RPC, Teredo, IPHTTPS, RPCEPMap, PlayToDiscovery и т.д.)
                            rule.protocol = Protocol.ANY
                    
                    def parse_ports(port_val):
                        """Парсит порты из PowerShell JSON.
                        Может быть: число, строка с числом, диапазон '5000-5020', массив "['80'", None.
                        """
                        if port_val is None:
                            return None
                        port_str = str(port_val).strip()
                        if port_str in ("*", "Any", ""):
                            return None
                        # Убираем лишние символы от PowerShell JSON массивов: "['80'" -> "80"
                        port_str = port_str.strip("[]' ")
                        result = []
                        for part in port_str.split(","):
                            part = part.strip().strip("'").strip()
                            if not part:
                                continue
                            try:
                                # Пробуем как число
                                result.append(int(part))
                            except ValueError:
                                # Если диапазон вида '5000-5020' — берём начало
                                if '-' in part:
                                    try:
                                        start = int(part.split('-')[0].strip())
                                        result.append(start)
                                    except ValueError:
                                        pass
                                # Иначе игнорируем (нечисловые значения)
                        return result if result else None
                    
                    rule.local_ports = parse_ports(item.get("LocalPort"))
                    rule.remote_ports = parse_ports(item.get("RemotePort"))
                    
                    local_addr = item.get("LocalAddress")
                    if local_addr and str(local_addr) not in ("*", "Any", ""):
                        rule.local_addresses = [a.strip() for a in str(local_addr).split(",") if a.strip()]
                    
                    remote_addr = item.get("RemoteAddress")
                    if remote_addr and str(remote_addr) not in ("*", "Any", ""):
                        rule.remote_addresses = [a.strip() for a in str(remote_addr).split(",") if a.strip()]
                    
                    rule.application_path = item.get("ApplicationName") or None
                    rule.interface_types = item.get("InterfaceTypes", "All")
                    
                    rules.append(rule)
                except Exception as e:
                    logger.warning(f"Failed to parse rule from PowerShell JSON: {e}")
            
            return rules
            
        except subprocess.TimeoutExpired:
            logger.error("PowerShell list_rules timed out after 30s")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"PowerShell list_rules JSON parse error: {e}")
            return None
        except Exception as e:
            logger.error(f"PowerShell list_rules failed: {e}")
            return None
    
    def _list_rules_com(self) -> List[FirewallRule]:
        """Запасной вариант: получает правила через COM API.
        
        Использует Dispatch("HNetCfg.FwPolicy2"). Для свежих данных после удаления
        используется PowerShell (list_rules), который не подвержен ROT-кэшированию.
        """
        import time
        start_time = time.time()
        try:
            # 1. Обновляем политику фаервола (mpssvc перечитывает реестр)
            self._refresh_policy()
            
            # 2. Используем Dispatch (CoCreateInstance недоступен — CLSID не зарегистрирован)
            import pythoncom
            pythoncom.CoInitialize()
            fwPolicy2 = self.win32com.Dispatch("HNetCfg.FwPolicy2")
            
            # Сохраняем в self.fwPolicy2 для других методов
            self.fwPolicy2 = fwPolicy2
            
            rules_collection = fwPolicy2.Rules
            count = rules_collection.Count
            logger.info(f"_list_rules_com: Dispatch FwPolicy2, правил: {count}")
            
            result = []
            for i, rule in enumerate(rules_collection):
                try:
                    fw_rule = self._com_rule_to_firewall_rule(rule)
                    result.append(fw_rule)
                except Exception as e:
                    logger.warning(f"Failed to convert rule at index {i}: {e}")
                if i > 0 and i % 1000 == 0:
                    elapsed = time.time() - start_time
                    logger.debug(f"_list_rules_com progress: {i} rules, {elapsed:.2f}s")
            
            elapsed = time.time() - start_time
            logger.info(f"_list_rules_com: {len(result)} rules in {elapsed:.2f}s")
            return result
        except Exception as e:
            logger.error(f"_list_rules_com failed: {e}", exc_info=True)
            return []

    def add_rule(self, rule: FirewallRule) -> bool:
        """Добавляет правило в Windows Firewall."""
        try:
            new_rule = self.win32com.Dispatch("HNetCfg.FWRule")
            new_rule.Name = rule.name
            new_rule.Description = rule.description
            new_rule.Enabled = rule.enabled
            new_rule.Action = self._action_to_com(rule.action)
            new_rule.Direction = self._direction_to_com(rule.direction)
            new_rule.Protocol = self._protocol_to_com(rule.protocol)
            if rule.application_path:
                new_rule.ApplicationName = rule.application_path
            if rule.local_ports:
                new_rule.LocalPorts = ",".join(str(p) for p in rule.local_ports)
            if rule.remote_ports:
                new_rule.RemotePorts = ",".join(str(p) for p in rule.remote_ports)
            if rule.local_addresses:
                new_rule.LocalAddresses = ",".join(rule.local_addresses)
            if rule.remote_addresses:
                new_rule.RemoteAddresses = ",".join(rule.remote_addresses)
            new_rule.InterfaceTypes = rule.interface_types
            self.fwPolicy2.Rules.Add(new_rule)
            logger.info(f"Rule added: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to add rule {rule.name}: {e}")
            return False

    def delete_rule(self, rule_id: str, display_name: Optional[str] = None) -> bool:
        """
        Удаляет правило по имени (в Windows Firewall нет ID, используем имя).
        Использует PowerShell с быстрым таймаутом и fallback на COM.
        
        Аргументы:
            rule_id: Внутренний ID правила (PowerShell Name) — для удаления через PowerShell.
            display_name: Человекочитаемое имя (PowerShell DisplayName) — для COM fallback.
                         Если не указан, используется rule_id.
        """
        # Сначала пытаемся удалить через PowerShell (быстрее, если права есть)
        if self._delete_rule_via_powershell(rule_id):
            return True
        
        # Если PowerShell не сработал, пробуем COM с уменьшенными попытками
        com_name = display_name or rule_id
        logger.warning(f"PowerShell удаление не удалось, пробуем COM для правила '{com_name}'")
        if self._delete_rule_via_com(com_name):
            return True
        
        # Если и COM не сработал, правило либо не существует, либо недоступно
        logger.warning(f"Правило не удалось удалить ни одним методом: '{rule_id}' (display_name='{com_name}')")
        return False

    def _delete_rule_via_com(self, rule_name: str, max_attempts: int = 2) -> bool:
        """Пытается удалить правило через COM API с повторными попытками.
        Использует Dispatch для создания FwPolicy2 (CoCreateInstance недоступен,
        т.к. CLSID не зарегистрирован в системе). Для свежих данных после удаления
        используется PowerShell (list_rules), который не подвержен ROT-кэшированию.
        """
        import pythoncom
        import threading
        
        def _create_fw_policy2():
            """Создаёт новый FwPolicy2 через Dispatch.
            CoCreateInstance не используется — CLSID не зарегистрирован в системе.
            """
            pythoncom.CoInitialize()
            return self.win32com.Dispatch("HNetCfg.FwPolicy2")
        
        def com_delete():
            pythoncom.CoInitialize()
            try:
                fwPolicy2 = _create_fw_policy2()
                rules = fwPolicy2.Rules
                
                target_rule = None
                for rule in rules:
                    if rule.Name == rule_name:
                        target_rule = rule
                        break
                
                if not target_rule:
                    logger.debug(f"Правило '{rule_name}' не найдено в COM коллекции")
                    return True  # Правила нет — считаем удалённым
                
                rules.Remove(target_rule)
                logger.debug(f"Правило '{rule_name}' удалено через COM")
                
                # Проверяем свежим объектом
                fwPolicy2 = _create_fw_policy2()
                rules = fwPolicy2.Rules
                still_exists = any(rule.Name == rule_name for rule in rules)
                if not still_exists:
                    logger.info(f"Правило '{rule_name}' успешно удалено через COM")
                    return True
                else:
                    logger.warning(f"Правило '{rule_name}' всё ещё присутствует после удаления")
                    return False
            except Exception as e:
                logger.warning(f"Ошибка COM удаления правила '{rule_name}': {e}")
                return False
            finally:
                pythoncom.CoUninitialize()
        
        # Если мы в главном потоке, можно вызывать напрямую
        if threading.current_thread() is threading.main_thread():
            for attempt in range(1, max_attempts + 1):
                try:
                    # Создаём свежий COM-объект через Dispatch
                    fwPolicy2 = _create_fw_policy2()
                    rules = fwPolicy2.Rules
                    
                    # Ищем правило
                    target_rule = None
                    for rule in rules:
                        if rule.Name == rule_name:
                            target_rule = rule
                            break
                    
                    if not target_rule:
                        logger.debug(f"Правило '{rule_name}' не найдено в COM коллекции (попытка {attempt})")
                        return True  # Правила нет — считаем удалённым
                    
                    # Удаляем
                    rules.Remove(target_rule)
                    logger.debug(f"Правило '{rule_name}' удалено через COM (попытка {attempt})")
                    
                    # Принудительно освобождаем COM-кэш
                    pythoncom.CoFreeUnusedLibraries()
                    time.sleep(0.1)  # Даём время системе применить изменения
                    
                    # Проверяем свежим объектом
                    fwPolicy2 = _create_fw_policy2()
                    rules = fwPolicy2.Rules
                    
                    # Проверяем, осталось ли правило
                    still_exists = any(rule.Name == rule_name for rule in rules)
                    if not still_exists:
                        logger.info(f"Правило '{rule_name}' успешно удалено через COM")
                        return True
                    else:
                        logger.warning(f"Правило '{rule_name}' всё ещё присутствует после удаления (попытка {attempt})")
                        
                except Exception as e:
                    logger.warning(f"Ошибка COM удаления правила '{rule_name}' (попытка {attempt}): {e}")
                    # Принудительно освобождаем COM-объекты
                    try:
                        pythoncom.CoFreeUnusedLibraries()
                    except:
                        pass
                
                if attempt < max_attempts:
                    time.sleep(0.3)  # Уменьшенная пауза перед следующей попыткой
            
            return False
        else:
            # В стороннем потоке используем безопасную обёртку
            for attempt in range(1, max_attempts + 1):
                success = com_delete()
                if success:
                    return True
                if attempt < max_attempts:
                    time.sleep(0.3)
            return False

    def _delete_rule_via_powershell(self, rule_name: str) -> bool:
        """Удаляет правило через PowerShell командой Remove-NetFirewallRule."""
        import time
        start_time = time.time()
        try:
            # Экранируем кавычки в имени правила
            escaped_name = rule_name.replace("'", "''")
            
            # Упрощённая команда с явным таймаутом и проверкой прав
            ps_command = (
                "$ProgressPreference = 'SilentlyContinue'; "
                "$ErrorActionPreference = 'Stop'; "  # Останавливаемся при ошибке
                f"Remove-NetFirewallRule -Name '{escaped_name}' -Confirm:$false -ErrorAction Stop 2>&1"
            )
            command = ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_command]
            result = subprocess.run(
                command,
                capture_output=True,
                text=False,  # Не text=True — на русской Windows это CP1251
                shell=False,
                timeout=30
            )
            elapsed = time.time() - start_time
            if result.returncode == 0:
                logger.info(f"Правило '{rule_name}' удалено через PowerShell (по Name) за {elapsed:.2f} сек")
                return True
            
            # Если не удалось по Name, пробуем по DisplayName
            logger.debug(f"Удаление по Name не удалось, пробуем по DisplayName для '{rule_name}'")
            ps_command_display = (
                "$ProgressPreference = 'SilentlyContinue'; "
                "$ErrorActionPreference = 'Stop'; "
                f"Get-NetFirewallRule -DisplayName '{escaped_name}' -ErrorAction Stop | "
                f"Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop 2>&1"
            )
            command_display = ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_command_display]
            start_display = time.time()
            result_display = subprocess.run(
                command_display,
                capture_output=True,
                text=False,
                shell=False,
                timeout=30
            )
            elapsed_display = time.time() - start_display
            if result_display.returncode == 0:
                logger.info(f"Правило '{rule_name}' удалено через PowerShell (по DisplayName) за {elapsed_display:.2f} сек")
                return True
            
            # Проверим, возможно, правило уже не существует
            check_command = (
                "$ProgressPreference = 'SilentlyContinue'; "
                "$ErrorActionPreference = 'Stop'; "
                f"Get-NetFirewallRule -Name '{escaped_name}' -ErrorAction Stop 2>&1"
            )
            check = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", check_command],
                capture_output=True,
                text=False,
                shell=False,
                timeout=10
            )
            # Декодируем stderr как UTF-8 для проверки "ObjectNotFound"
            check_stderr = check.stderr.decode('utf-8', errors='replace') if check.stderr else ""
            if check.returncode != 0 or "ObjectNotFound" in check_stderr:
                logger.debug(f"Правило '{rule_name}' не существует (уже удалено)")
                return True
            
            # Если правило всё ещё существует, попробуем принудительное удаление через COM внутри PowerShell
            logger.warning(f"PowerShell не смог удалить правило '{rule_name}'. Пробуем COM через PowerShell...")
            ps_com_command = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$fw = New-Object -ComObject HNetCfg.FwPolicy2
$rules = $fw.Rules
$target = $rules | Where-Object {{ $_.Name -eq '{escaped_name}' }}
if ($target) {{
    $rules.Remove($target)
    Write-Host 'Удалено через COM'
}}
"""
            result_com = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_com_command],
                capture_output=True,
                text=False,
                shell=False,
                timeout=30
            )
            # Декодируем stdout как UTF-8 для проверки русской строки
            com_stdout = result_com.stdout.decode('utf-8', errors='replace') if result_com.stdout else ""
            if result_com.returncode == 0 and 'Удалено через COM' in com_stdout:
                logger.info(f"Правило '{rule_name}' удалено через COM внутри PowerShell")
                return True
            
            # Декодируем stderr для лога
            stderr_text = result.stderr.decode('utf-8', errors='replace') if result.stderr else ""
            logger.warning(f"PowerShell не смог удалить правило '{rule_name}': {stderr_text[:200]}")
            return False
        except subprocess.TimeoutExpired:
            logger.error(f"Таймаут при удалении правила '{rule_name}' через PowerShell")
            return False
        except Exception as e:
            logger.error(f"Ошибка при удалении правила '{rule_name}' через PowerShell: {e}")
            return False

    def update_rule(self, rule: FirewallRule) -> bool:
        """Обновляет правило (удаляет старое и добавляет новое)."""
        # В Windows Firewall нет прямого обновления, поэтому удаляем и создаём заново.
        # rule.name = DisplayName (человекочитаемое имя) — подходит и для PowerShell, и для COM.
        if self.delete_rule(rule.name, display_name=rule.name):
            return self.add_rule(rule)
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Включает правило."""
        rules = self.fwPolicy2.Rules
        for rule in rules:
            if rule.Name == rule_id:
                try:
                    rule.Enabled = True
                    logger.info(f"Rule enabled: {rule_id}")
                    return True
                except Exception as e:
                    logger.error(f"Failed to enable rule {rule_id}: {e}")
                    return False
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Отключает правило."""
        rules = self.fwPolicy2.Rules
        for rule in rules:
            if rule.Name == rule_id:
                try:
                    rule.Enabled = False
                    logger.info(f"Rule disabled: {rule_id}")
                    return True
                except Exception as e:
                    logger.error(f"Failed to disable rule {rule_id}: {e}")
                    return False
        return False

    def _refresh_policy(self):
        """Обновляет политику фаервола через netsh advfirewall refresh.
        Заставляет Windows Firewall service (mpssvc) перечитать конфигурацию из реестра.
        """
        try:
            subprocess.run(
                ["netsh", "advfirewall", "refresh"],
                capture_output=True,
                timeout=10
            )
            logger.debug("Политика фаервола обновлена через netsh advfirewall refresh")
        except Exception as e:
            logger.warning(f"Не удалось обновить политику фаервола: {e}")

    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Возвращает правило по имени через COM (быстро, без PowerShell).
        Используется только для просмотра/редактирования одного правила.
        Для получения свежего списка правил используется list_rules() (PowerShell).
        
        В COM: rule.Name = DisplayName (человекочитаемое имя).
        В PowerShell: rule.Name = внутренний ID, rule.DisplayName = человекочитаемое имя.
        Поэтому ищем по DisplayName (rule.name), а не по внутреннему ID (rule.id).
        """
        try:
            rules = self.fwPolicy2.Rules
            for rule in rules:
                # COM rule.Name = DisplayName. Ищем по rule.name (DisplayName из PowerShell).
                if rule.Name == rule_id:
                    return self._com_rule_to_firewall_rule(rule)
        except Exception as e:
            logger.warning(f"get_rule COM failed for '{rule_id}': {e}")
        return None

    # Вспомогательные методы преобразования

    def _com_rule_to_firewall_rule(self, com_rule) -> FirewallRule:
        """Преобразует COM-объект правила в FirewallRule."""
        rule = FirewallRule()
        
        # Вспомогательная функция безопасного получения атрибута
        def safe_getattr(obj, attr, default=None):
            try:
                return getattr(obj, attr)
            except Exception:
                return default
        
        # Безопасное извлечение атрибутов
        try:
            rule.id = safe_getattr(com_rule, "Name", "")
        except Exception:
            rule.id = ""
        rule.name = rule.id
        
        rule.description = safe_getattr(com_rule, "Description", "")
        
        try:
            rule.enabled = bool(safe_getattr(com_rule, "Enabled", False))
        except Exception:
            rule.enabled = False
        
        try:
            action_val = safe_getattr(com_rule, "Action", 1)
            rule.action = self._com_action_to_action(action_val)
        except Exception:
            rule.action = RuleAction.ALLOW
        
        try:
            direction_val = safe_getattr(com_rule, "Direction", 1)
            rule.direction = self._com_direction_to_direction(direction_val)
        except Exception:
            rule.direction = RuleDirection.INBOUND
        
        try:
            protocol_val = safe_getattr(com_rule, "Protocol", 256)
            rule.protocol = self._com_protocol_to_protocol(protocol_val)
        except Exception:
            rule.protocol = Protocol.ANY
        
        rule.application_path = safe_getattr(com_rule, "ApplicationName", None)
        
        local_ports_str = safe_getattr(com_rule, "LocalPorts", "")
        rule.local_ports = self._parse_ports(local_ports_str)
        
        remote_ports_str = safe_getattr(com_rule, "RemotePorts", "")
        rule.remote_ports = self._parse_ports(remote_ports_str)
        
        local_addrs_str = safe_getattr(com_rule, "LocalAddresses", "")
        rule.local_addresses = self._parse_addresses(local_addrs_str)
        
        remote_addrs_str = safe_getattr(com_rule, "RemoteAddresses", "")
        rule.remote_addresses = self._parse_addresses(remote_addrs_str)
        
        rule.interface_types = safe_getattr(com_rule, "InterfaceTypes", "All")
        
        # created_at и updated_at неизвестны
        return rule

    @staticmethod
    def _parse_ports(ports_str: str) -> Optional[List[int]]:
        if not ports_str or ports_str == "*":
            return None
        try:
            return [int(p.strip()) for p in ports_str.split(",") if p.strip()]
        except ValueError:
            return None

    @staticmethod
    def _parse_addresses(addrs_str: str) -> Optional[List[str]]:
        if not addrs_str or addrs_str == "*":
            return None
        return [a.strip() for a in addrs_str.split(",") if a.strip()]

    @staticmethod
    def _action_to_com(action: RuleAction) -> int:
        # 0 = Block, 1 = Allow
        return 1 if action == RuleAction.ALLOW else 0

    @staticmethod
    def _com_action_to_action(com_action: int) -> RuleAction:
        return RuleAction.ALLOW if com_action == 1 else RuleAction.BLOCK

    @staticmethod
    def _direction_to_com(direction: RuleDirection) -> int:
        # 1 = Inbound, 2 = Outbound
        return 1 if direction == RuleDirection.INBOUND else 2

    @staticmethod
    def _com_direction_to_direction(com_direction: int) -> RuleDirection:
        return RuleDirection.INBOUND if com_direction == 1 else RuleDirection.OUTBOUND

    @staticmethod
    def _protocol_to_com(protocol: Protocol) -> int:
        # 256 = ANY, 6 = TCP, 17 = UDP, 1 = ICMP
        mapping = {
            Protocol.ANY: 256,
            Protocol.TCP: 6,
            Protocol.UDP: 17,
            Protocol.ICMP: 1,
        }
        return mapping.get(protocol, 256)

    @staticmethod
    def _com_protocol_to_protocol(com_protocol: int) -> Protocol:
        mapping = {
            256: Protocol.ANY,
            6: Protocol.TCP,
            17: Protocol.UDP,
            1: Protocol.ICMP,
        }
        return mapping.get(com_protocol, Protocol.ANY)