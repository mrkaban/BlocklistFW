"""
Диалог проверки и включения брандмауэра Windows.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QGroupBox, QMessageBox, QProgressBar
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon, QFont

from firewall_manager import FirewallManager


class FirewallStatusDialog(QDialog):
    """
    Диалог, показывающий статус брандмауэра Windows и предлагающий включить его.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.fw_manager = FirewallManager()
        self.setWindowTitle("Проверка брандмауэра Windows")
        self.setWindowIcon(QIcon("resources/icons/app_icon.ico"))
        self.setMinimumWidth(500)
        self.setModal(True)
        self.result_action = None  # "run", "run_without", "close"
        
        self.init_ui()
        self.refresh_status()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Заголовок
        title_label = QLabel("Проверка состояния брандмауэра Windows")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(12)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Группа статуса
        self.status_group = QGroupBox("Текущий статус")
        status_layout = QVBoxLayout()
        
        self.status_label = QLabel("Загрузка...")
        self.status_label.setWordWrap(True)
        status_layout.addWidget(self.status_label)
        
        self.detailed_label = QLabel("")
        self.detailed_label.setWordWrap(True)
        status_layout.addWidget(self.detailed_label)
        
        self.status_group.setLayout(status_layout)
        layout.addWidget(self.status_group)
        
        # Группа управления
        control_group = QGroupBox("Управление брандмауэром")
        control_layout = QVBoxLayout()
        
        self.enable_button = QPushButton("Включить брандмауэр")
        self.enable_button.clicked.connect(self.enable_firewall)
        self.enable_button.setEnabled(False)
        control_layout.addWidget(self.enable_button)
        
        self.disable_button = QPushButton("Выключить брандмауэр (не рекомендуется)")
        self.disable_button.clicked.connect(self.disable_firewall)
        self.disable_button.setEnabled(False)
        control_layout.addWidget(self.disable_button)
        
        self.auto_checkbox = QCheckBox("Автоматически проверять статус при запуске")
        self.auto_checkbox.setChecked(True)
        control_layout.addWidget(self.auto_checkbox)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Пояснение
        warning_label = QLabel(
            "<b>Внимание:</b> Без включенного брандмауэра Windows правила блокировки не будут работать. "
            "Рекомендуется включить брандмауэр для полной функциональности."
        )
        warning_label.setWordWrap(True)
        warning_label.setStyleSheet("color: #d35400; background-color: #fff3cd; padding: 8px; border-radius: 4px;")
        layout.addWidget(warning_label)
        
        # Прогресс-бар для операции
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Кнопки действий
        action_button_layout = QHBoxLayout()
        
        self.run_button = QPushButton("Запустить")
        self.run_button.clicked.connect(self.on_run_clicked)
        self.run_button.setEnabled(False)  # по умолчанию выключена
        action_button_layout.addWidget(self.run_button)
        
        self.run_without_button = QPushButton("Запустить без брандмауэра")
        self.run_without_button.clicked.connect(self.on_run_without_clicked)
        action_button_layout.addWidget(self.run_without_button)
        
        self.close_button = QPushButton("Закрыть")
        self.close_button.clicked.connect(self.on_close_clicked)
        action_button_layout.addWidget(self.close_button)
        
        layout.addLayout(action_button_layout)
        
        # Кнопка обновления статуса
        refresh_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Обновить статус")
        self.refresh_button.clicked.connect(self.refresh_status)
        refresh_layout.addWidget(self.refresh_button)
        refresh_layout.addStretch()
        layout.addLayout(refresh_layout)
        
        self.setLayout(layout)
    
    def refresh_status(self):
        """Обновить отображение статуса брандмауэра."""
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # индикатор занятости
        QTimer.singleShot(100, self._update_status)  # небольшой delay для отзывчивости
    
    def _update_status(self):
        try:
            # Получаем детальный статус всех профилей
            details = self.fw_manager.get_firewall_status()
            if details:
                profiles = details.get("profiles", {})
                # Проверяем, включены ли ВСЕ профили
                all_enabled = all(profiles.values())
                any_enabled = any(profiles.values())
                
                # Формируем общий статус
                if all_enabled:
                    status_text = "Включен для всех профилей"
                    color = "green"
                elif any_enabled:
                    status_text = "Включен частично (некоторые профили выключены)"
                    color = "orange"
                else:
                    status_text = "Выключен для всех профилей"
                    color = "red"
                
                self.status_label.setText(
                    f'<span style="color:{color}; font-weight:bold;">Брандмауэр Windows: {status_text}</span>'
                )
                
                # Детальная информация по каждому профилю
                lines = []
                for profile, state in profiles.items():
                    lines.append(f"{profile}: {'Включен' if state else 'Выключен'}")
                self.detailed_label.setText("\n".join(lines))
                
                # Активировать кнопки
                self.enable_button.setEnabled(not all_enabled)
                self.disable_button.setEnabled(any_enabled)
                self.run_button.setEnabled(any_enabled)
            else:
                self.status_label.setText("Не удалось получить статус брандмауэра.")
                self.detailed_label.setText("")
                self.enable_button.setEnabled(False)
                self.disable_button.setEnabled(False)
                self.run_button.setEnabled(False)
            
        except Exception as e:
            self.status_label.setText(f"Ошибка при проверке статуса: {str(e)}")
            self.detailed_label.setText("")
        finally:
            self.progress_bar.setVisible(False)
    
    def enable_firewall(self):
        """Включить брандмауэр."""
        reply = QMessageBox.question(
            self, "Подтверждение",
            "Включить брандмауэр Windows? Это повысит безопасность вашей системы.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            QTimer.singleShot(100, self._perform_enable)
    
    def _perform_enable(self):
        try:
            success = self.fw_manager.enable_firewall()
            if success:
                QMessageBox.information(self, "Успех", "Брандмауэр Windows успешно включен.")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось включить брандмауэр. Возможно, недостаточно прав.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)
            self.refresh_status()
    
    def disable_firewall(self):
        """Выключить брандмауэр."""
        reply = QMessageBox.warning(
            self, "Предупреждение",
            "Выключение брандмауэра Windows снизит безопасность вашей системы.\n"
            "Вы уверены, что хотите продолжить?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            QTimer.singleShot(100, self._perform_disable)
    
    def _perform_disable(self):
        try:
            success = self.fw_manager.disable_firewall()
            if success:
                QMessageBox.information(self, "Успех", "Брандмауэр Windows выключен.")
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось выключить брандмауэр.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка: {str(e)}")
        finally:
            self.progress_bar.setVisible(False)
            self.refresh_status()
    
    def on_run_clicked(self):
        """Обработчик нажатия кнопки 'Запустить'."""
        self.result_action = "run"
        self.accept()
    
    def on_run_without_clicked(self):
        """Обработчик нажатия кнопки 'Запустить без брандмауэра'."""
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Предупреждение")
        msg_box.setText("Вы запускаете программу без включенного брандмауэра Windows.\n"
                       "Основной функционал блокировки правил может не работать.\n"
                       "Продолжить?")
        yes_btn = msg_box.addButton("Да", QMessageBox.YesRole)
        no_btn = msg_box.addButton("Нет", QMessageBox.NoRole)
        msg_box.setDefaultButton(no_btn)
        msg_box.exec()
        if msg_box.clickedButton() == yes_btn:
            self.result_action = "run_without"
            self.accept()
        else:
            # остаёмся в диалоге
            pass
    
    def on_close_clicked(self):
        """Обработчик нажатия кнопки 'Закрыть'."""
        self.result_action = "close"
        self.reject()


def check_firewall_on_startup(parent=None):
    """
    Функция для проверки брандмауэра при запуске приложения.
    Проверяет ВСЕ профили (Domain, Private, Public), а не только активный.
    Если хотя бы один профиль выключен, показывает диалог.
    Возвращает True если пользователь выбрал запуск (с брандмауэром или без),
    False если пользователь выбрал закрыть программу.
    """
    try:
        fw_manager = FirewallManager()
        # Получаем статус всех профилей
        status = fw_manager.get_firewall_status()
        profiles = status.get("profiles", {}) if status else {}
        
        # Проверяем, включены ли ВСЕ профили
        all_enabled = all(profiles.values()) if profiles else True
        
        if not all_enabled:
            dialog = FirewallStatusDialog(parent)
            result = dialog.exec()
            # Если диалог закрыт через reject (кнопка "Закрыть")
            if result == QDialog.Rejected or dialog.result_action == "close":
                return False
            # Иначе пользователь выбрал запуск (run или run_without)
            return True
        return True
    except Exception:
        # Если проверка не удалась, пропускаем и продолжаем
        return True