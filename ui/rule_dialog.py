"""
Диалог создания и редактирования правил фаервола.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLineEdit, QComboBox, QCheckBox, QPushButton,
    QListWidget, QListWidgetItem, QMessageBox, QLabel
)
from PySide6.QtCore import Qt

from core.rule import FirewallRule, RuleAction, RuleDirection, Protocol
from core.validator import validate_rule, RuleValidationError


class RuleDialog(QDialog):
    """Диалог для создания/редактирования правила."""

    def __init__(self, parent=None, rule=None):
        super().__init__(parent)
        self.rule = rule or FirewallRule()
        self.init_ui()
        self.load_rule_data()

    def init_ui(self):
        """Инициализация интерфейса диалога."""
        self.update_window_title()
        self.setMinimumWidth(500)

        layout = QVBoxLayout()

        # Форма с полями
        form = QFormLayout()

        self.name_edit = QLineEdit()
        form.addRow("Имя правила:", self.name_edit)

        self.description_edit = QLineEdit()
        form.addRow("Описание:", self.description_edit)

        self.action_combo = QComboBox()
        self.action_combo.addItems(["Разрешить", "Заблокировать"])
        form.addRow("Действие:", self.action_combo)

        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["Входящий", "Исходящий"])
        form.addRow("Направление:", self.direction_combo)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["Любой", "TCP", "UDP", "ICMP"])
        form.addRow("Протокол:", self.protocol_combo)

        self.local_ports_edit = QLineEdit()
        self.local_ports_edit.setPlaceholderText("80,443,8080")
        form.addRow("Локальные порты:", self.local_ports_edit)

        self.remote_ports_edit = QLineEdit()
        self.remote_ports_edit.setPlaceholderText("8080,9000-9010")
        form.addRow("Удалённые порты:", self.remote_ports_edit)

        self.local_addresses_edit = QLineEdit()
        self.local_addresses_edit.setPlaceholderText("192.168.1.0/24,10.0.0.1")
        form.addRow("Локальные адреса:", self.local_addresses_edit)

        self.remote_addresses_edit = QLineEdit()
        self.remote_addresses_edit.setPlaceholderText("8.8.8.8,0.0.0.0/0")
        form.addRow("Удалённые адреса:", self.remote_addresses_edit)

        self.application_path_edit = QLineEdit()
        self.application_path_edit.setPlaceholderText("C:\\Program Files\\app.exe")
        form.addRow("Путь к приложению:", self.application_path_edit)

        self.enabled_check = QCheckBox("Включено")
        self.enabled_check.setChecked(True)
        form.addRow("", self.enabled_check)

        layout.addLayout(form)

        # Кнопки
        button_layout = QHBoxLayout()
        self.ok_btn = QPushButton("OK")
        self.ok_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addStretch()
        button_layout.addWidget(self.ok_btn)
        button_layout.addWidget(self.cancel_btn)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def load_rule_data(self):
        """Загрузка данных правила в форму."""
        self.name_edit.setText(self.rule.name)
        self.description_edit.setText(self.rule.description)
        self.action_combo.setCurrentIndex(0 if self.rule.action == RuleAction.ALLOW else 1)
        self.direction_combo.setCurrentIndex(0 if self.rule.direction == RuleDirection.INBOUND else 1)
        protocol_index = {"any": 0, "tcp": 1, "udp": 2, "icmp": 3}.get(self.rule.protocol.value, 0)
        self.protocol_combo.setCurrentIndex(protocol_index)
        if self.rule.local_ports:
            self.local_ports_edit.setText(",".join(str(p) for p in self.rule.local_ports))
        if self.rule.remote_ports:
            self.remote_ports_edit.setText(",".join(str(p) for p in self.rule.remote_ports))
        if self.rule.local_addresses:
            self.local_addresses_edit.setText(",".join(self.rule.local_addresses))
        if self.rule.remote_addresses:
            self.remote_addresses_edit.setText(",".join(self.rule.remote_addresses))
        if self.rule.application_path:
            self.application_path_edit.setText(self.rule.application_path)
        self.enabled_check.setChecked(self.rule.enabled)
        self.update_window_title()

    def get_rule(self) -> FirewallRule:
        """Создание объекта правила из данных формы."""
        rule = FirewallRule()
        rule.name = self.name_edit.text().strip()
        rule.description = self.description_edit.text().strip()
        rule.action = RuleAction.ALLOW if self.action_combo.currentIndex() == 0 else RuleAction.BLOCK
        rule.direction = RuleDirection.INBOUND if self.direction_combo.currentIndex() == 0 else RuleDirection.OUTBOUND
        protocol_map = {0: Protocol.ANY, 1: Protocol.TCP, 2: Protocol.UDP, 3: Protocol.ICMP}
        rule.protocol = protocol_map[self.protocol_combo.currentIndex()]
        rule.enabled = self.enabled_check.isChecked()

        # Парсинг портов
        local_ports_text = self.local_ports_edit.text().strip()
        if local_ports_text:
            rule.local_ports = self._parse_ports(local_ports_text)
        remote_ports_text = self.remote_ports_edit.text().strip()
        if remote_ports_text:
            rule.remote_ports = self._parse_ports(remote_ports_text)

        # Парсинг адресов
        local_addrs_text = self.local_addresses_edit.text().strip()
        if local_addrs_text:
            rule.local_addresses = [a.strip() for a in local_addrs_text.split(",") if a.strip()]
        remote_addrs_text = self.remote_addresses_edit.text().strip()
        if remote_addrs_text:
            rule.remote_addresses = [a.strip() for a in remote_addrs_text.split(",") if a.strip()]

        app_path = self.application_path_edit.text().strip()
        if app_path:
            rule.application_path = app_path

        return rule

    def _parse_ports(self, text: str):
        """Парсинг строки портов (поддержка диапазонов и списков)."""
        ports = []
        for part in text.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-"))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        return ports if ports else None

    def update_window_title(self):
        """Обновление заголовка окна с именем правила."""
        rule_name = self.rule.name.strip()
        if rule_name:
            self.setWindowTitle(f"Правило - {rule_name}")
        else:
            self.setWindowTitle("Правило фаервола")

    def accept(self):
        """Обработка нажатия OK с валидацией."""
        try:
            rule = self.get_rule()
            validate_rule(rule)
            super().accept()
        except RuleValidationError as e:
            QMessageBox.warning(self, "Ошибка валидации", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Неизвестная ошибка: {e}")