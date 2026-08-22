"""
Диалог добавления/редактирования источника угроз.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QCheckBox, QSpinBox, QPushButton, QMessageBox,
    QGroupBox, QFormLayout, QFileDialog
)
from PySide6.QtCore import Qt

from services.threat_intelligence import ThreatFeed, FeedFormat


class ThreatFeedDialog(QDialog):
    """Диалог для создания или редактирования источника угроз."""

    def __init__(self, parent=None, feed: ThreatFeed = None):
        super().__init__(parent)
        self.feed = feed
        self.setWindowTitle("Источник угроз" if feed else "Новый источник угроз")
        self.setMinimumWidth(500)
        self.init_ui()
        if feed:
            self.load_feed_data()

    def init_ui(self):
        layout = QVBoxLayout()

        # Основные поля
        form = QFormLayout()

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Например: Spamhaus DROP List")
        form.addRow("Название:", self.name_edit)

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com/threats.txt")
        form.addRow("URL:", self.url_edit)

        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("C:\\путь\\к\\файлу.txt")
        self.file_browse_btn = QPushButton("Обзор...")
        self.file_browse_btn.clicked.connect(self.browse_file)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_edit)
        file_layout.addWidget(self.file_browse_btn)
        form.addRow("Локальный файл:", file_layout)

        self.format_combo = QComboBox()
        self.format_combo.addItems([fmt.value.upper() for fmt in FeedFormat])
        form.addRow("Формат:", self.format_combo)

        self.update_interval_spin = QSpinBox()
        self.update_interval_spin.setRange(300, 2592000)  # от 5 минут до 30 дней
        self.update_interval_spin.setValue(86400)
        self.update_interval_spin.setSuffix(" секунд")
        form.addRow("Интервал обновления:", self.update_interval_spin)

        self.enabled_check = QCheckBox("Включён")
        self.enabled_check.setChecked(True)
        form.addRow("", self.enabled_check)

        self.description_edit = QLineEdit()
        self.description_edit.setPlaceholderText("Описание источника")
        form.addRow("Описание:", self.description_edit)

        layout.addLayout(form)

        # Группа аутентификации
        auth_group = QGroupBox("Аутентификация (опционально)")
        auth_layout = QFormLayout()
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["none", "basic", "api_key"])
        auth_layout.addRow("Тип:", self.auth_type_combo)
        self.auth_data_edit = QLineEdit()
        self.auth_data_edit.setPlaceholderText('{"username":"user","password":"pass"} или {"api_key":"key"}')
        auth_layout.addRow("Данные (JSON):", self.auth_data_edit)
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)

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

    def browse_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Выберите файл списка угроз", "", "Текстовые файлы (*.txt);;Все файлы (*)")
        if filepath:
            self.file_edit.setText(filepath)

    def load_feed_data(self):
        """Заполняет поля данными существующего источника."""
        if not self.feed:
            return
        self.name_edit.setText(self.feed.name)
        self.url_edit.setText(self.feed.url or "")
        self.file_edit.setText(self.feed.file_path or "")
        self.format_combo.setCurrentText(self.feed.format.value.upper())
        self.update_interval_spin.setValue(self.feed.update_interval)
        self.enabled_check.setChecked(self.feed.enabled)
        self.description_edit.setText(self.feed.description)
        self.auth_type_combo.setCurrentText(self.feed.auth_type)
        if self.feed.auth_data:
            import json
            self.auth_data_edit.setText(json.dumps(self.feed.auth_data))

    def get_feed(self) -> ThreatFeed:
        """Создаёт объект ThreatFeed из введённых данных."""
        import json
        from datetime import datetime

        feed = ThreatFeed()
        feed.name = self.name_edit.text().strip()
        url = self.url_edit.text().strip()
        feed.url = url if url else None
        file_path = self.file_edit.text().strip()
        feed.file_path = file_path if file_path else None
        feed.format = FeedFormat(self.format_combo.currentText().lower())
        feed.update_interval = self.update_interval_spin.value()
        feed.enabled = self.enabled_check.isChecked()
        feed.description = self.description_edit.text().strip()
        feed.auth_type = self.auth_type_combo.currentText()
        auth_data = self.auth_data_edit.text().strip()
        feed.auth_data = json.loads(auth_data) if auth_data else None
        feed.last_update = datetime.now() if feed.enabled else None
        return feed

    def accept(self):
        """Проверка перед закрытием."""
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Ошибка", "Введите название источника.")
            return
        if not self.url_edit.text().strip() and not self.file_edit.text().strip():
            QMessageBox.warning(self, "Ошибка", "Укажите URL или локальный файл.")
            return
        super().accept()