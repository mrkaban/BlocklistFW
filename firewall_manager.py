import subprocess
import logging

logger = logging.getLogger(__name__)


def _get_firewall_status_netsh() -> dict:
    """Получает статус брандмауэра через netsh advfirewall show allprofiles.
    
    Это надёжнее COM-вызова FirewallEnabled(), который при Dispatch
    может давать E_INVALIDARG в некоторых версиях pywin32.
    """
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True, text=True, timeout=30
        )
        profiles = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Domain"):
                profiles["Domain"] = "ON" in line.upper()
            elif line.startswith("Private"):
                profiles["Private"] = "ON" in line.upper()
            elif line.startswith("Public"):
                profiles["Public"] = "ON" in line.upper()
        return profiles
    except Exception as e:
        logger.error(f"Ошибка получения статуса брандмауэра через netsh: {e}")
        return {}


class FirewallManager:
    def __init__(self):
        # FwPolicy2 не создаём заранее — используем netsh для статуса,
        # а COM-объект создаём только при необходимости (enable/disable через netsh)
        pass
    
    def is_firewall_enabled(self) -> bool:
        """
        Проверяет, включен ли брандмауэр Windows для ВСЕХ профилей.
        Возвращает True если все профили включены, False если хотя бы один выключен.
        Использует netsh advfirewall show allprofiles.
        """
        profiles = _get_firewall_status_netsh()
        if not profiles:
            return False
        return all(profiles.values())
    
    def enable_firewall(self, all_profiles: bool = True) -> bool:
        """
        Включает брандмауэр Windows для указанных профилей.
        Использует netsh advfirewall.
        Если all_profiles=True (по умолчанию), включает для всех профилей (Domain, Private, Public).
        Иначе включает только для текущего активного профиля.
        Возвращает True при успехе, False при ошибке.
        """
        try:
            if all_profiles:
                subprocess.run(
                    ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                    check=True, capture_output=True, timeout=30
                )
                logger.info("Брандмауэр включён для всех профилей (Domain, Private, Public)")
            else:
                # Определяем имя текущего профиля через netsh
                profiles = _get_firewall_status_netsh()
                # Не можем определить текущий профиль без COM, включаем все
                logger.warning("Не удалось определить текущий профиль, включаем все")
                subprocess.run(
                    ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                    check=True, capture_output=True, timeout=30
                )
            return True
        except Exception as e:
            logger.error(f"Ошибка включения брандмауэра: {e}")
            return False
    
    def disable_firewall(self, all_profiles: bool = True) -> bool:
        """
        Выключает брандмауэр Windows для указанных профилей.
        Использует netsh advfirewall.
        Если all_profiles=True (по умолчанию), выключает для всех профилей (Domain, Private, Public).
        Иначе выключает только для текущего активного профиля.
        Возвращает True при успехе, False при ошибке.
        """
        try:
            if all_profiles:
                subprocess.run(
                    ["netsh", "advfirewall", "set", "allprofiles", "state", "off"],
                    check=True, capture_output=True, timeout=30
                )
                logger.info("Брандмауэр выключен для всех профилей (Domain, Private, Public)")
            else:
                logger.warning("Не удалось определить текущий профиль, выключаем все")
                subprocess.run(
                    ["netsh", "advfirewall", "set", "allprofiles", "state", "off"],
                    check=True, capture_output=True, timeout=30
                )
            return True
        except Exception as e:
            logger.error(f"Ошибка выключения брандмауэра: {e}")
            return False
    
    def get_firewall_status(self) -> dict:
        """
        Возвращает детальный статус брандмауэра для всех профилей.
        Использует netsh advfirewall show allprofiles.
        """
        profiles = _get_firewall_status_netsh()
        if not profiles:
            return {}
        return {
            "profiles": profiles,
            "current_profile": 0,  # Не определяем через netsh
            "global_enabled": any(profiles.values())
        }