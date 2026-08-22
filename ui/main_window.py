"""
Главное окно приложения BlocklistFW на PySide6.
"""

import sys
import ipaddress
import json
import os
import logging
from datetime import datetime
from typing import Optional, List
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QMessageBox,
    QComboBox, QLineEdit, QCheckBox, QGroupBox, QFileDialog,
    QDialog, QListWidget, QListWidgetItem,
    QProgressDialog, QSpinBox, QTextBrowser
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon

logger = logging.getLogger(__name__)

from core.engine import WindowsFirewallEngine
from core.rule import FirewallRule, RuleAction, RuleDirection, Protocol
from core.rule_deleter import FirewallRuleDeleter
from core.fast_rule_deleter import FastRuleDeleter
from services.traffic_monitor import TrafficMonitor
from services.traffic_stats import TrafficStats
from services.event_logger import EventType, EventLevel, logger as global_logger
from services.backup_manager import BackupManager
from services.threat_intelligence import (
    ThreatIntelligenceManager,
    ThreatRuleGenerator, DomainResolver
)
from services.configuration_manager import ConfigurationManager
from ui.firewall_dialog import check_firewall_on_startup
from ui.delete_worker import DeleteRulesWorker

# Matplotlib для графиков
import matplotlib
matplotlib.use('QtAgg')
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


def _format_speed(bytes_per_sec: float) -> str:
    """Человекочитаемое форматирование скорости в байтах/сек.

    Подбирает подходящую единицу измерения по величине:
    до 1023 Б/с -> байты, далее КБ/МБ/ГБ/ТБ (деление на 1024).
    """
    value = float(bytes_per_sec)
    units = ["Б/с", "КБ/с", "МБ/с", "ГБ/с", "ТБ/с"]
    unit_index = 0
    # Для отображения используем 1023.95, чтобы при 1024 ровно сразу показывался КБ
    while abs(value) >= 1024 and unit_index < len(units) - 1:
        value /= 1024.0
        unit_index += 1
    if unit_index == 0:
        # Целые байты
        return f"{value:.0f} {units[unit_index]}"
    if value >= 100 or value == int(value):
        return f"{value:.0f} {units[unit_index]}"
    if value >= 10:
        return f"{value:.1f} {units[unit_index]}"
    return f"{value:.2f} {units[unit_index]}"


def _feed_to_dict(feed) -> dict:
    """Преобразует источник угроз в словарь для сохранения в резервную копию."""
    return {
        "id": feed.id,
        "name": feed.name,
        "url": feed.url,
        "file_path": feed.file_path,
        "format": feed.format.value,
        "update_interval": feed.update_interval,
        "last_update": feed.last_update.isoformat() if feed.last_update else None,
        "enabled": feed.enabled,
        "description": feed.description,
        "auth_type": feed.auth_type,
        "auth_data": feed.auth_data,
    }


def _feed_from_dict(data: dict):
    """Создаёт объект ThreatFeed из словаря резервной копии."""
    from services.threat_intelligence import ThreatFeed, FeedFormat
    return ThreatFeed(
        id=data.get("id"),
        name=data.get("name", ""),
        url=data.get("url"),
        file_path=data.get("file_path"),
        format=FeedFormat(data.get("format", "txt")),
        update_interval=data.get("update_interval", 86400),
        last_update=datetime.fromisoformat(data["last_update"]) if data.get("last_update") else None,
        enabled=data.get("enabled", True),
        description=data.get("description", ""),
        auth_type=data.get("auth_type", "none"),
        auth_data=data.get("auth_data"),
    )


def _entry_to_dict(entry) -> dict:
    """Преобразует запись об угрозе в словарь для сохранения в резервную копию."""
    return {
        "id": entry.id,
        "feed_id": entry.feed_id,
        "ip": entry.ip,
        "cidr": entry.cidr,
        "domain": entry.domain,
        "threat_type": entry.threat_type.value,
        "first_seen": entry.first_seen.isoformat(),
        "last_seen": entry.last_seen.isoformat(),
        "resolved_ips": entry.resolved_ips,
        "metadata": entry.metadata,
    }


def _entry_from_dict(data: dict):
    """Создаёт объект ThreatEntry из словаря резервной копии."""
    from services.threat_intelligence import ThreatEntry, ThreatType

    def _parse_dt(value):
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return datetime.now()

    return ThreatEntry(
        id=data.get("id"),
        feed_id=data.get("feed_id", ""),
        ip=data.get("ip"),
        cidr=data.get("cidr"),
        domain=data.get("domain"),
        threat_type=ThreatType(data.get("threat_type", "unknown")),
        first_seen=_parse_dt(data.get("first_seen")),
        last_seen=_parse_dt(data.get("last_seen")),
        resolved_ips=data.get("resolved_ips") or [],
        metadata=data.get("metadata") or {},
    )


class SmartHeader(QHeaderView):
    """QHeaderView, который совмещает Stretch (автоподгон) и Interactive (ручное изменение).
    
    - Все колонки растягиваются при изменении ширины окна
    - Пользователь может изменить ширину любой колонки вручную
    - После ручного изменения, колонка фиксирует свою ширину
    - Остальные колонки продолжают растягиваться
    """
    
    def __init__(self, parent=None):
        super().__init__(Qt.Horizontal, parent)
        self._stretch_mode = True  # Изначально все колонки в режиме Stretch
        self._initialized = False  # Флаг, что начальная отрисовка завершена
        self.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.sectionResized.connect(self._on_section_resized)
    
    def _on_section_resized(self, logicalIndex, oldSize, newSize):
        """При ручном изменении размера колонки переключаем её в Interactive.
        
        Игнорируем сигнал во время начальной отрисовки (oldSize == 0),
        так как Qt испускает sectionResized при первом размещении колонок.
        """
        # Игнорируем сигнал во время начальной отрисовки
        if not self._initialized:
            return
        # Игнорируем если oldSize == 0 (начальная установка размера)
        if oldSize <= 0:
            return
        if self._stretch_mode:
            self._stretch_mode = False
            # Переключаем изменённую колонку в Interactive
            self.setSectionResizeMode(logicalIndex, QHeaderView.ResizeMode.Interactive)
    
    def showEvent(self, event):
        """После первого показа окна считаем, что начальная отрисовка завершена."""
        super().showEvent(event)
        if not self._initialized:
            self._initialized = True
    
    def resizeEvent(self, event):
        """При изменении ширины окна пропорционально растягиваем колонки."""
        if not self._stretch_mode:
            old_width = event.oldSize().width() if event.oldSize().isValid() else self.width()
            if old_width > 0:
                ratio = self.width() / old_width
                for i in range(self.count()):
                    if self.sectionResizeMode(i) == QHeaderView.ResizeMode.Interactive:
                        new_size = max(30, int(self.sectionSize(i) * ratio))
                        self.resizeSection(i, new_size)
        super().resizeEvent(event)


class MainWindow(QMainWindow):
    """Главное окно фаервола с вкладками."""

    def __init__(self):
        super().__init__()
        self.engine = WindowsFirewallEngine()
        self.monitor = TrafficMonitor()
        self.traffic_stats = TrafficStats(max_history=60)  # история на 60 секунд
        self.event_logger = global_logger  # используем глобальный экземпляр логгера
        self.backup_manager = BackupManager()
        self.threat_manager = ThreatIntelligenceManager()
        self.domain_resolver = DomainResolver()
        self.rule_generator = ThreatRuleGenerator(self.engine, self.domain_resolver)
        self.config_manager = ConfigurationManager()
        self.config_manager.load()  # загружаем сохранённые настройки
        self.init_ui()
        self.load_rules()

    def init_ui(self):
        """Инициализация пользовательского интерфейса."""
        self.setWindowTitle("BlocklistFW")
        self.setGeometry(100, 100, 1200, 700)

        # Центральный виджет с вкладками
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        # Вкладка "Монитор" (открывается первой при запуске)
        self.monitor_tab = QWidget()
        self.init_monitor_tab()
        self.tab_widget.addTab(self.monitor_tab, "Монитор")

        # Вкладка "Правила"
        self.rules_tab = QWidget()
        self.init_rules_tab()
        self.tab_widget.addTab(self.rules_tab, "Правила")

        # Вкладка "Угрозы"
        self.threats_tab = QWidget()
        self.init_threats_tab()
        self.tab_widget.addTab(self.threats_tab, "Угрозы")

        # Вкладка "Логи" (заглушка)
        self.logs_tab = QWidget()
        self.init_logs_tab()
        self.tab_widget.addTab(self.logs_tab, "Логи")

        # Вкладка "Настройки" (заглушка)
        self.settings_tab = QWidget()
        self.init_settings_tab()
        self.tab_widget.addTab(self.settings_tab, "Настройки")

        # Вкладка "О программе"
        self.about_tab = QWidget()
        self.init_about_tab()
        self.tab_widget.addTab(self.about_tab, "О программе")

        # Статусбар
        self.statusBar().showMessage("Готово")

    def _setup_rules_table(self, table: QTableWidget):
        """Настраивает таблицу правил с общими параметрами."""
        table.setColumnCount(8)
        table.setHorizontalHeaderLabels([
            "ID", "Имя", "Действие", "Направление", "Протокол",
            "Локальные порты", "Удалённые адреса", "Включено"
        ])
        # Используем SmartHeader для совмещения автоподгона и ручного изменения
        smart_header = SmartHeader()
        table.setHorizontalHeader(smart_header)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)  # запрет редактирования текста
        table.doubleClicked.connect(self.on_rule_double_click)  # открытие окна по двойному клику
        # Встроенная сортировка по клику на заголовки
        table.setSortingEnabled(True)

    def init_rules_tab(self):
        """Инициализация вкладки с правилами."""
        layout = QVBoxLayout()

        # Панель кнопок
        button_layout = QHBoxLayout()
        self.add_rule_btn = QPushButton("Добавить правило")
        self.add_rule_btn.clicked.connect(self.on_add_rule)
        self.edit_rule_btn = QPushButton("Редактировать")
        self.edit_rule_btn.clicked.connect(self.on_edit_rule)
        self.delete_rule_btn = QPushButton("Удалить")
        self.delete_rule_btn.clicked.connect(self.on_delete_rule)
        self.refresh_btn = QPushButton("Обновить")
        self.refresh_btn.clicked.connect(self.load_rules)
        self.import_btn = QPushButton("Импорт")
        self.import_btn.clicked.connect(self.on_import_rules)
        self.export_btn = QPushButton("Экспорт")
        self.export_btn.clicked.connect(self.on_export_rules)

        button_layout.addWidget(self.add_rule_btn)
        button_layout.addWidget(self.edit_rule_btn)
        button_layout.addWidget(self.delete_rule_btn)
        button_layout.addWidget(self.refresh_btn)
        button_layout.addWidget(self.import_btn)
        button_layout.addWidget(self.export_btn)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        # Поиск по правилам (работает по всем отображаемым полям)
        search_layout = QHBoxLayout()
        self.rule_search_edit = QLineEdit()
        self.rule_search_edit.setPlaceholderText(
            "Поиск по правилам (имя, ID, действие, направление, протокол, порты, адреса)..."
        )
        self.rule_search_edit.textChanged.connect(self.on_rule_search_changed)
        search_layout.addWidget(self.rule_search_edit, 1)
        clear_search_btn = QPushButton("Сбросить поиск")
        clear_search_btn.clicked.connect(self.on_clear_rule_search)
        search_layout.addWidget(clear_search_btn)
        layout.addLayout(search_layout)

        # Вкладки для разделения правил по направлению
        self.rules_tab_widget = QTabWidget()
        
        # Вкладка "Все правила"
        self.rules_table_all = QTableWidget()
        self._setup_rules_table(self.rules_table_all)
        self.rules_tab_widget.addTab(self.rules_table_all, "Все правила")
        
        # Вкладка "Входящие"
        self.rules_table_inbound = QTableWidget()
        self._setup_rules_table(self.rules_table_inbound)
        self.rules_tab_widget.addTab(self.rules_table_inbound, "Входящие")
        
        # Вкладка "Исходящие"
        self.rules_table_outbound = QTableWidget()
        self._setup_rules_table(self.rules_table_outbound)
        self.rules_tab_widget.addTab(self.rules_table_outbound, "Исходящие")
        
        layout.addWidget(self.rules_tab_widget)
        
        # Для обратной совместимости оставляем self.rules_table ссылкой на таблицу "Все правила"
        self.rules_table = self.rules_table_all

        self.rules_tab.setLayout(layout)

    def init_monitor_tab(self):
        """Инициализация вкладки мониторинга."""
        layout = QVBoxLayout()

        # Панель кнопок
        button_layout = QHBoxLayout()
        self.refresh_monitor_btn = QPushButton("Обновить")
        self.refresh_monitor_btn.clicked.connect(self.update_monitor_table)
        self.clear_cache_btn = QPushButton("Очистить кэш процессов")
        self.clear_cache_btn.clicked.connect(self.clear_monitor_cache)
        self.clear_graph_btn = QPushButton("Очистить график")
        self.clear_graph_btn.clicked.connect(self.clear_traffic_graph)
        button_layout.addWidget(self.refresh_monitor_btn)
        button_layout.addWidget(self.clear_cache_btn)
        button_layout.addWidget(self.clear_graph_btn)
        button_layout.addStretch()

        layout.addLayout(button_layout)

        # Панель настройки интервала обновления
        interval_group = QGroupBox("Настройка обновления")
        interval_layout = QHBoxLayout()
        interval_layout.addWidget(QLabel("Интервал обновления (сек):"))
        self.monitor_interval_spin = QSpinBox()
        self.monitor_interval_spin.setRange(1, 60)
        self.monitor_interval_spin.setValue(self.config_manager.get("monitor_update_interval_seconds", 1))
        self.monitor_interval_spin.setSuffix(" сек")
        interval_layout.addWidget(self.monitor_interval_spin)
        self.monitor_interval_apply_btn = QPushButton("Применить")
        self.monitor_interval_apply_btn.clicked.connect(self.update_monitor_interval)
        interval_layout.addWidget(self.monitor_interval_apply_btn)
        interval_layout.addStretch()
        interval_group.setLayout(interval_layout)
        layout.addWidget(interval_group)

        # Панель фильтров
        filter_group = QGroupBox("Фильтры подключений")
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel("IP-адрес:"))
        self.monitor_filter_ip_edit = QLineEdit()
        self.monitor_filter_ip_edit.setPlaceholderText("192.168.1.1 или подсеть 192.168.1.0/24")
        filter_layout.addWidget(self.monitor_filter_ip_edit)

        filter_layout.addWidget(QLabel("Тип:"))
        self.monitor_filter_type_combo = QComboBox()
        self.monitor_filter_type_combo.addItems(["Любой", "Локальный адрес", "Удалённый адрес"])
        filter_layout.addWidget(self.monitor_filter_type_combo)

        self.monitor_filter_auto = QCheckBox("Автофильтрация")
        self.monitor_filter_auto.setChecked(True)
        filter_layout.addWidget(self.monitor_filter_auto)

        self.monitor_filter_apply_btn = QPushButton("Применить фильтр")
        self.monitor_filter_apply_btn.clicked.connect(self.update_monitor_table)
        filter_layout.addWidget(self.monitor_filter_apply_btn)

        filter_layout.addStretch()
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

        # График трафика
        graph_widget = QWidget()
        graph_layout = QVBoxLayout()
        self.graph_figure = Figure(figsize=(8, 3), dpi=100)
        self.graph_canvas = FigureCanvas(self.graph_figure)
        self.graph_ax = self.graph_figure.add_subplot(111)
        self.graph_ax.set_title("Скорость сетевого трафика")
        self.graph_ax.set_xlabel("Время (сек)")
        self.graph_ax.set_ylabel("Скорость (Байт/с)")
        self.graph_ax.grid(True)
        self.graph_ax.legend(["Исходящий", "Входящий"])
        graph_layout.addWidget(self.graph_canvas)
        graph_widget.setLayout(graph_layout)
        layout.addWidget(graph_widget)

        # Таблица подключений
        self.monitor_table = QTableWidget()
        self.monitor_table.setColumnCount(8)
        self.monitor_table.setHorizontalHeaderLabels([
            "Протокол", "Локальный адрес", "Локальный порт",
            "Удалённый адрес", "Удалённый порт", "Состояние", "Процесс", "PID"
        ])
        self.monitor_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.monitor_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.monitor_table)

        # Статус
        self.monitor_status = QLabel("Подключений: 0")
        layout.addWidget(self.monitor_status)

        self.monitor_tab.setLayout(layout)

        # Таймер для автообновления таблицы и графика с настраиваемым интервалом
        interval_seconds = self.config_manager.get("monitor_update_interval_seconds", 1)
        interval_ms = interval_seconds * 1000
        
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.update_monitor_table)
        self.monitor_timer.start(interval_ms)

        self.graph_timer = QTimer()
        self.graph_timer.timeout.connect(self.update_traffic_graph)
        self.graph_timer.start(interval_ms)

    def update_monitor_interval(self):
        """Обновляет интервал таймеров мониторинга на основе значения спинбокса."""
        interval_seconds = self.monitor_interval_spin.value()
        interval_ms = interval_seconds * 1000
        
        # Обновляем интервалы таймеров
        if self.monitor_timer:
            self.monitor_timer.setInterval(interval_ms)
        if self.graph_timer:
            self.graph_timer.setInterval(interval_ms)
        
        # Сохраняем настройку
        self.config_manager.set("monitor_update_interval_seconds", interval_seconds)
        self.config_manager.save()
        
        # Показываем сообщение в статусной строке
        self.statusBar().showMessage(f"Интервал обновления монитора установлен на {interval_seconds} секунд", 3000)

    def init_logs_tab(self):
        """Инициализация вкладки логов."""
        layout = QVBoxLayout()

        # Панель фильтров
        filter_group = QGroupBox("Фильтры")
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel("Уровень:"))
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["Все", "INFO", "WARNING", "ERROR", "SECURITY"])
        filter_layout.addWidget(self.log_level_combo)

        filter_layout.addWidget(QLabel("Тип события:"))
        self.log_type_combo = QComboBox()
        self.log_type_combo.addItems(["Все", "RULE_ADDED", "RULE_DELETED", "RULE_UPDATED",
                                      "CONNECTION_BLOCKED", "CONNECTION_ALLOWED", "MONITOR_UPDATE",
                                      "SETTINGS_CHANGED", "ERROR"])
        filter_layout.addWidget(self.log_type_combo)

        filter_layout.addWidget(QLabel("Поиск:"))
        self.log_search_edit = QLineEdit()
        self.log_search_edit.setPlaceholderText("Сообщение или детали...")
        filter_layout.addWidget(self.log_search_edit)

        self.log_auto_refresh = QCheckBox("Автообновление")
        self.log_auto_refresh.setChecked(True)
        filter_layout.addWidget(self.log_auto_refresh)

        self.log_refresh_btn = QPushButton("Обновить")
        self.log_refresh_btn.clicked.connect(self.update_logs_table)
        filter_layout.addWidget(self.log_refresh_btn)

        self.log_clear_btn = QPushButton("Очистить журнал")
        self.log_clear_btn.clicked.connect(self.clear_logs)
        filter_layout.addWidget(self.log_clear_btn)

        filter_layout.addStretch()
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

        # Таблица логов
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(6)
        self.logs_table.setHorizontalHeaderLabels([
            "Время", "Уровень", "Тип", "Сообщение", "Источник", "Детали"
        ])
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.logs_table)

        # Статус
        self.logs_status = QLabel("Записей: 0")
        layout.addWidget(self.logs_status)

        self.logs_tab.setLayout(layout)

        # Таймер автообновления (каждые 5 секунд)
        self.logs_timer = QTimer()
        self.logs_timer.timeout.connect(self.update_logs_table)
        self.logs_timer.start(5000)
        
        # Связываем чекбокс автообновления с таймером
        self.log_auto_refresh.stateChanged.connect(self._toggle_logs_auto_refresh)
        
        # Первоначальное обновление таблицы
        self.update_logs_table()
        
        # Добавляем тестовую запись в лог, чтобы убедиться, что вкладка работает
        global_logger.info(
            EventType.MONITOR_UPDATE,
            "Вкладка 'Логи' инициализирована. Журнал событий готов к работе."
        )

    def init_settings_tab(self):
        """Инициализация вкладки настроек."""
        layout = QVBoxLayout()
        layout.setSpacing(10)


        # Группа резервного копирования
        backup_group = QGroupBox("Резервное копирование")
        backup_layout = QVBoxLayout()

        # Пояснение о том, какие данные сохраняются
        backup_hint = QLabel(
            "Кнопки управляют резервными копиями правил брандмауэра, "
            "списков URL-источников угроз и списков IP-адресов."
        )
        backup_hint.setWordWrap(True)
        backup_hint.setStyleSheet("color: #555;")
        backup_layout.addWidget(backup_hint)

        backup_buttons_layout = QHBoxLayout()
        self.create_backup_btn = QPushButton("Создать резервную копию")
        self.create_backup_btn.clicked.connect(self.on_create_backup)
        backup_buttons_layout.addWidget(self.create_backup_btn)
        
        self.restore_backup_btn = QPushButton("Восстановить из резервной копии")
        self.restore_backup_btn.clicked.connect(self.on_restore_backup)
        backup_buttons_layout.addWidget(self.restore_backup_btn)
        
        self.manage_backups_btn = QPushButton("Управление резервными копиями")
        self.manage_backups_btn.clicked.connect(self.on_manage_backups)
        backup_buttons_layout.addWidget(self.manage_backups_btn)
        
        backup_layout.addLayout(backup_buttons_layout)
        
        # Опции резервного копирования
        options_layout = QHBoxLayout()
        self.include_logs_check = QCheckBox("Включать логи в резервную копию")
        self.include_logs_check.setChecked(True)
        options_layout.addWidget(self.include_logs_check)
        backup_layout.addLayout(options_layout)
        
        backup_group.setLayout(backup_layout)
        layout.addWidget(backup_group)

        # Группа исключений IP из списка угроз
        exclude_group = QGroupBox("Исключение IP из Списка Угроз")
        exclude_layout = QVBoxLayout()

        exclude_hint = QLabel(
            "Позволяет исключить IP-адрес из работы компонента «Угрозы».\n"
            "Введите только IP (например, 192.168.1.5). Для диапазона укажите маску "
            "(например, 192.168.1.0/18). Если маска не указана, добавляется один IP (/32)."
        )
        exclude_hint.setWordWrap(True)
        exclude_hint.setStyleSheet("color: #555;")
        exclude_layout.addWidget(exclude_hint)

        # Список исключённых адресов + кнопки управления
        exclude_row = QHBoxLayout()
        self.excluded_ips_list = QListWidget()
        self.excluded_ips_list.setMaximumHeight(140)
        exclude_row.addWidget(self.excluded_ips_list, 1)

        exclude_controls = QVBoxLayout()
        self.excluded_ip_input = QLineEdit()
        self.excluded_ip_input.setPlaceholderText("IP или IP/маска (например, 1.2.3.4)")
        exclude_controls.addWidget(self.excluded_ip_input)

        add_excl_btn = QPushButton("Добавить")
        add_excl_btn.clicked.connect(self._add_excluded_ip)
        exclude_controls.addWidget(add_excl_btn)

        remove_excl_btn = QPushButton("Удалить")
        remove_excl_btn.clicked.connect(self._remove_excluded_ip)
        exclude_controls.addWidget(remove_excl_btn)
        exclude_row.addLayout(exclude_controls)

        exclude_layout.addLayout(exclude_row)

        exclude_group.setLayout(exclude_layout)
        layout.addWidget(exclude_group)

        layout.addStretch()
        self.settings_tab.setLayout(layout)

    def _load_excluded_ips(self):
        """Загружает список исключённых IP/CIDR в виджет."""
        self.excluded_ips_list.clear()
        excluded = self.config_manager.get("excluded_ips", []) or []
        for item in excluded:
            self.excluded_ips_list.addItem(item)

    def _parse_ip_or_cidr(self, text):
        """Проверяет строку как IP или CIDR. Возвращает нормализованную строку или None."""
        text = text.strip()
        if not text:
            return None
        try:
            if "/" in text:
                network = ipaddress.ip_network(text, strict=False)
                return str(network)
            addr = ipaddress.ip_address(text)
            return str(addr)
        except ValueError:
            return None

    def _add_excluded_ip(self):
        """Добавляет IP/CIDR в список исключений."""
        value = self._parse_ip_or_cidr(self.excluded_ip_input.text())
        if value is None:
            QMessageBox.warning(
                self, "Неверный формат",
                "Введите корректный IP-адрес или диапазон с маской "
                "(например, 1.2.3.4 или 10.0.0.0/8)."
            )
            return
        existing = self.config_manager.get("excluded_ips", []) or []
        if value in existing:
            QMessageBox.information(self, "Уже добавлено", "Этот IP уже находится в списке исключений.")
            return
        existing.append(value)
        self.config_manager.set("excluded_ips", existing)
        self.config_manager.save()
        self.excluded_ip_input.clear()
        self._load_excluded_ips()

    def _remove_excluded_ip(self):
        """Удаляет выбранный IP/CIDR из списка исключений."""
        current = self.excluded_ips_list.currentItem()
        if not current:
            QMessageBox.warning(self, "Внимание", "Выберите запись для удаления.")
            return
        value = current.text()
        existing = self.config_manager.get("excluded_ips", []) or []
        if value in existing:
            existing.remove(value)
        self.config_manager.set("excluded_ips", existing)
        self.config_manager.save()
        self._load_excluded_ips()

    def init_about_tab(self):
        """Инициализация вкладки 'О программе'."""
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)

        # Заголовок
        title_label = QLabel("BlocklistFW")
        title_font = title_label.font()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        # Подзаголовок
        subtitle_label = QLabel("Программа управления брандмауэром Windows с Threat Intelligence")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #555;")
        layout.addWidget(subtitle_label)

        # HTML-описание
        about_html = """
        <div style="font-size: 12pt; line-height: 1.5;">
        <p><strong>Версия:</strong> 1.0.0 (бета)</p>
        <p><strong>Автор:</strong> Алексей Черемных</p>
        <p><strong>Сайт:</strong> <a href="https://alekseycheremnykh.ru">alekseycheremnykh.ru</a></p>
        <p><strong>Лицензия:</strong> MIT (см. файл LICENSE)</p>
        <hr>
        <p>Программа предоставляет графический интерфейс для управления правилами Windows Firewall,
        загрузки и применения списков угроз из открытых источников, мониторинга сетевой активности
        и ведения логов событий.</p>
        <p><strong>Основные возможности:</strong></p>
        <ul>
            <li>Создание, редактирование, удаление правил брандмауэра</li>
            <li>Загрузка угроз из внешних источников (CINS Army, ET Block и др.)</li>
            <li>Автоматическое применение правил блокировки для IP-адресов угроз</li>
            <li>Мониторинг активных сетевых подключений в реальном времени</li>
            <li>Ведение журнала событий с фильтрацией</li>
            <li>Резервное копирование и восстановление конфигурации</li>
        </ul>
        <hr>
        <p><strong>Технологии:</strong> Python 3, PySide6, Windows Firewall API (win32com), SQLite.</p>
        <p><strong>Исходный код:</strong> доступен на GitHub.</p>
        </div>
        """
        about_text = QTextBrowser()
        about_text.setHtml(about_html)
        about_text.setOpenExternalLinks(True)
        about_text.setReadOnly(True)
        about_text.setMinimumHeight(400)
        layout.addWidget(about_text)

        # Кнопка закрытия
        close_button = QPushButton("Закрыть")
        close_button.clicked.connect(lambda: self.tab_widget.setCurrentIndex(0))
        close_button.setMaximumWidth(200)
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        layout.addStretch()
        self.about_tab.setLayout(layout)

    def init_threats_tab(self):
        """Инициализация вкладки Threat Intelligence."""
        layout = QVBoxLayout()
        layout.setSpacing(10)

        # Панель управления источниками
        feed_group = QGroupBox("Источники угроз")
        feed_layout = QVBoxLayout()

        # Кнопки управления источниками
        feed_buttons = QHBoxLayout()
        self.add_feed_btn = QPushButton("Добавить источник")
        self.add_feed_btn.clicked.connect(self.on_add_feed)
        feed_buttons.addWidget(self.add_feed_btn)

        self.edit_feed_btn = QPushButton("Редактировать")
        self.edit_feed_btn.clicked.connect(self.on_edit_feed)
        feed_buttons.addWidget(self.edit_feed_btn)

        self.delete_feed_btn = QPushButton("Удалить")
        self.delete_feed_btn.clicked.connect(self.on_delete_feed)
        feed_buttons.addWidget(self.delete_feed_btn)

        self.refresh_feeds_btn = QPushButton("Обновить все правила")
        self.refresh_feeds_btn.clicked.connect(self.on_refresh_feeds)
        feed_buttons.addWidget(self.refresh_feeds_btn)

        feed_buttons.addStretch()
        feed_layout.addLayout(feed_buttons)

        # Таблица источников
        self.feeds_table = QTableWidget()
        self.feeds_table.setColumnCount(6)
        self.feeds_table.setHorizontalHeaderLabels([
            "ID", "Название", "URL/Файл", "Формат", "Обновлено", "Включено"
        ])
        self.feeds_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.feeds_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.feeds_table.setEditTriggers(QTableWidget.NoEditTriggers)  # запрет редактирования ячеек
        self.feeds_table.doubleClicked.connect(lambda _index: self.on_edit_feed())  # открытие редактора
        feed_layout.addWidget(self.feeds_table)

        feed_group.setLayout(feed_layout)
        layout.addWidget(feed_group)

        # Панель управления записями угроз
        entries_group = QGroupBox("Угрозы")
        entries_layout = QVBoxLayout()

        # Фильтры
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Тип:"))
        self.threat_type_combo = QComboBox()
        self.threat_type_combo.addItems(["Все", "MALWARE", "PHISHING", "BOTNET", "SPAM", "SCANNER", "C2", "UNKNOWN"])
        filter_layout.addWidget(self.threat_type_combo)

        filter_layout.addWidget(QLabel("Источник:"))
        self.threat_feed_combo = QComboBox()
        self.threat_feed_combo.addItem("Все источники")
        filter_layout.addWidget(self.threat_feed_combo)

        filter_layout.addWidget(QLabel("Поиск:"))
        self.threat_search_edit = QLineEdit()
        self.threat_search_edit.setPlaceholderText("IP, домен, тип или источник...")
        filter_layout.addWidget(self.threat_search_edit)

        self.apply_filter_btn = QPushButton("Применить фильтр")
        self.apply_filter_btn.clicked.connect(self.on_apply_threat_filter)
        filter_layout.addWidget(self.apply_filter_btn)

        self.reset_filter_btn = QPushButton("Сбросить фильтр")
        self.reset_filter_btn.clicked.connect(self.on_reset_threat_filter)
        filter_layout.addWidget(self.reset_filter_btn)

        filter_layout.addStretch()
        entries_layout.addLayout(filter_layout)

        # Таблица записей
        self.threat_entries_table = QTableWidget()
        self.threat_entries_table.setColumnCount(6)
        self.threat_entries_table.setHorizontalHeaderLabels([
            "ID", "IP/Домен", "Тип", "Источник", "Добавлено", "CIDR"
        ])
        self.threat_entries_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.threat_entries_table.setSelectionBehavior(QTableWidget.SelectRows)
        entries_layout.addWidget(self.threat_entries_table)

        entries_group.setLayout(entries_layout)
        layout.addWidget(entries_group)

        # Панель действий
        action_group = QGroupBox("Действия")
        action_layout = QHBoxLayout()

        self.apply_rules_btn = QPushButton("Применить правила блокировки")
        self.apply_rules_btn.clicked.connect(self.on_apply_threat_rules)
        action_layout.addWidget(self.apply_rules_btn)

        self.delete_all_threat_rules_btn = QPushButton("Удалить все правила блокировки угроз")
        self.delete_all_threat_rules_btn.clicked.connect(self.on_delete_all_threat_rules)
        action_layout.addWidget(self.delete_all_threat_rules_btn)

        self.clear_cache_btn = QPushButton("Очистить кэш DNS")
        self.clear_cache_btn.clicked.connect(self.on_clear_dns_cache)
        action_layout.addWidget(self.clear_cache_btn)

        action_layout.addStretch()
        action_group.setLayout(action_layout)
        layout.addWidget(action_group)

        # Статус
        self.threat_status = QLabel("Источников: 0, записей: 0")
        layout.addWidget(self.threat_status)

        layout.addStretch()
        self.threats_tab.setLayout(layout)

        # Загрузка данных
        self.load_feeds_table()
        self.load_threat_entries_table()

    def load_rules(self):
        """Загрузка правил из движка, кэширование и отображение во всех таблицах."""
        try:
            # list_rules() сам пересоздаёт COM-объект FwPolicy2 при каждом вызове,
            # чтобы избежать отображения устаревших данных после удаления
            rules = self.engine.list_rules()

            # Разделяем правила по направлению (сравниваем через enum, не строки)
            from core.rule import RuleDirection
            inbound_rules = [r for r in rules if r.direction == RuleDirection.INBOUND]
            outbound_rules = [r for r in rules if r.direction == RuleDirection.OUTBOUND]

            # Кэшируем для поиска и последующей перефильтрации
            self._all_rules = rules
            self._inbound_rules = inbound_rules
            self._outbound_rules = outbound_rules
            self._apply_rule_search()

            threat_rules = [r for r in rules if r.name.startswith("ThreatIntel:")]
            logger.info(f"load_rules: всего правил={len(rules)}, ThreatIntel={len(threat_rules)}")

            self.statusBar().showMessage(
                f"Загружено правил: {len(rules)} (входящих: {len(inbound_rules)}, "
                f"исходящих: {len(outbound_rules)})"
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить правила: {e}")

    def _rule_matches(self, rule, needle: str) -> bool:
        """Проверяет, содержит ли правило искомый текст в любом отображаемом поле."""
        haystack = " ".join([
            rule.id or "",
            rule.name or "",
            rule.description or "",
            self._translate_action(rule.action),
            self._translate_direction(rule.direction),
            self._translate_protocol(rule.protocol),
            ", ".join(str(p) for p in rule.local_ports or []),
            ", ".join(rule.remote_addresses or []),
            "Да" if rule.enabled else "Нет",
        ]).lower()
        return needle in haystack

    def _apply_rule_search(self):
        """Фильтрует кэшированные правила по тексту поиска и заполняет все таблицы."""
        if hasattr(self, "rule_search_edit"):
            needle = self.rule_search_edit.text().strip().lower()
        else:
            needle = ""
        all_rules = getattr(self, "_all_rules", [])
        inbound = getattr(self, "_inbound_rules", [])
        outbound = getattr(self, "_outbound_rules", [])

        if needle:
            all_rules = [r for r in all_rules if self._rule_matches(r, needle)]
            inbound = [r for r in inbound if self._rule_matches(r, needle)]
            outbound = [r for r in outbound if self._rule_matches(r, needle)]

        self._populate_table(self.rules_table_all, all_rules)
        self._populate_table(self.rules_table_inbound, inbound)
        self._populate_table(self.rules_table_outbound, outbound)

    def on_rule_search_changed(self, text):
        """Обработчик изменения текста поиска по правилам."""
        self._apply_rule_search()

    def on_clear_rule_search(self):
        """Сброс поиска по правилам."""
        self.rule_search_edit.clear()
        self._apply_rule_search()

    @staticmethod
    def _translate_action(action: RuleAction) -> str:
        """Переводит действие правила на русский."""
        return {
            RuleAction.ALLOW: "Разрешить",
            RuleAction.BLOCK: "Блокировать",
        }.get(action, str(action.value))

    @staticmethod
    def _translate_direction(direction: RuleDirection) -> str:
        """Переводит направление на русский."""
        return {
            RuleDirection.INBOUND: "Входящий",
            RuleDirection.OUTBOUND: "Исходящий",
        }.get(direction, str(direction.value))

    @staticmethod
    def _translate_protocol(protocol: Protocol) -> str:
        """Переводит протокол на русский."""
        return {
            Protocol.ANY: "Любой",
            Protocol.TCP: "TCP",
            Protocol.UDP: "UDP",
            Protocol.ICMP: "ICMP",
        }.get(protocol, str(protocol.value))

    @staticmethod
    def _translate_address(addr: str) -> str:
        """Переводит стандартные адреса на русский."""
        addr_map = {
            "Any": "Любой",
            "LocalSubnet": "Локальная подсеть",
            "Internet": "Интернет",
            "All": "Все",
            "All Interfaces": "Все интерфейсы",
            "All Profiles": "Все профили",
        }
        return addr_map.get(addr, addr)

    def _populate_table(self, table: QTableWidget, rules: List[FirewallRule]):
        """Заполняет переданную таблицу списком правил (с сохранением сортировки)."""
        table.setUpdatesEnabled(False)
        was_sorting = table.isSortingEnabled()
        table.setSortingEnabled(False)
        table.setRowCount(len(rules))
        for row, rule in enumerate(rules):
            table.setItem(row, 0, QTableWidgetItem(rule.id))
            table.setItem(row, 1, QTableWidgetItem(rule.name))
            table.setItem(row, 2, QTableWidgetItem(self._translate_action(rule.action)))
            table.setItem(row, 3, QTableWidgetItem(self._translate_direction(rule.direction)))
            table.setItem(row, 4, QTableWidgetItem(self._translate_protocol(rule.protocol)))
            local_ports = ", ".join(str(p) for p in rule.local_ports) if rule.local_ports else ""
            table.setItem(row, 5, QTableWidgetItem(local_ports))
            if rule.remote_addresses:
                remote_addrs = ", ".join(self._translate_address(a) for a in rule.remote_addresses)
            else:
                remote_addrs = ""
            table.setItem(row, 6, QTableWidgetItem(remote_addrs))
            table.setItem(row, 7, QTableWidgetItem("Да" if rule.enabled else "Нет"))
        table.setSortingEnabled(was_sorting)
        table.setUpdatesEnabled(True)
        table.viewport().update()

    def _get_active_rules_table(self) -> QTableWidget:
        """Возвращает таблицу правил активной вкладки."""
        current_index = self.rules_tab_widget.currentIndex()
        if current_index == 0:  # Все правила
            return self.rules_table_all
        elif current_index == 1:  # Входящие
            return self.rules_table_inbound
        elif current_index == 2:  # Исходящие
            return self.rules_table_outbound
        else:
            return self.rules_table_all  # запасной вариант

    def on_add_rule(self):
        """Обработчик добавления правила."""
        from ui.rule_dialog import RuleDialog
        dialog = RuleDialog(self)
        if dialog.exec():
            rule = dialog.get_rule()
            try:
                success = self.engine.add_rule(rule)
                if success:
                    QMessageBox.information(self, "Успех", "Правило добавлено")
                    self.load_rules()
                else:
                    QMessageBox.warning(self, "Ошибка", "Не удалось добавить правило")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Исключение: {e}")

    def on_edit_rule(self):
        """Обработчик редактирования выбранного правила."""
        table = self._get_active_rules_table()
        selected = table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Внимание", "Выберите правило для редактирования")
            return
        row = selected[0].row()
        # колонка 0 = rule.id (внутренний ID из PowerShell Name)
        # колонка 1 = rule.name (DisplayName из PowerShell) — используем для COM
        rule_name = table.item(row, 1).text()
        rule = self.engine.get_rule(rule_name)
        if not rule:
            QMessageBox.warning(self, "Ошибка", "Правило не найдено")
            return

        from ui.rule_dialog import RuleDialog
        dialog = RuleDialog(self, rule)
        if dialog.exec():
            updated_rule = dialog.get_rule()
            success = self.engine.update_rule(updated_rule)
            if success:
                QMessageBox.information(self, "Успех", "Правило обновлено")
                self.load_rules()
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось обновить правило")

    def on_rule_double_click(self, index):
        """Обработчик двойного клика по строке таблицы правил."""
        # Определяем таблицу, которая отправила сигнал
        table = self.sender()
        if not isinstance(table, QTableWidget):
            table = self._get_active_rules_table()
        row = index.row()
        # колонка 0 = rule.id (внутренний ID из PowerShell Name)
        # колонка 1 = rule.name (DisplayName из PowerShell) — используем для COM
        rule_name = table.item(row, 1).text()
        rule = self.engine.get_rule(rule_name)
        if not rule:
            QMessageBox.warning(self, "Ошибка", "Правило не найдено")
            return

        from ui.rule_dialog import RuleDialog
        dialog = RuleDialog(self, rule)
        if dialog.exec():
            updated_rule = dialog.get_rule()
            success = self.engine.update_rule(updated_rule)
            if success:
                QMessageBox.information(self, "Успех", "Правило обновлено")
                self.load_rules()
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось обновить правило")

    def on_delete_rule(self):
        """Обработчик удаления выбранных правил (поддерживает множественный выбор)."""
        table = self._get_active_rules_table()
        selected_indexes = table.selectedIndexes()
        if not selected_indexes:
            QMessageBox.warning(self, "Внимание", "Выберите правило(а) для удаления")
            return
        
        # Получаем уникальные номера строк
        rows = set()
        for index in selected_indexes:
            rows.add(index.row())
        
        # Собираем информацию о выбранных правилах
        rules_to_delete = []
        for row in sorted(rows):
            rule_id = table.item(row, 0).text()
            rule_name = table.item(row, 1).text()
            rules_to_delete.append((rule_id, rule_name))
        
        if not rules_to_delete:
            return
        
        # Диалог подтверждения
        if len(rules_to_delete) == 1:
            message = f"Удалить правило '{rules_to_delete[0][1]}'?"
        else:
            message = f"Удалить выбранные правила ({len(rules_to_delete)} шт.)?"
            # Дополнительное предупреждение для большого количества правил
            if len(rules_to_delete) > 100:
                message += (
                    "\n\n⚠️ ВНИМАНИЕ: удаление такого количества правил может занять значительное время "
                    "(от нескольких минут до нескольких часов в зависимости от количества правил).\n\n"
                    "Рекомендуется:\n"
                    "• Убедиться, что у вас есть резервная копия правил\n"
                    "• Не прерывать операцию до её завершения\n"
                    "• Дождаться окончания удаления (прогресс будет отображаться в диалоге)"
                )
        
        reply = QMessageBox.question(
            self, "Подтверждение",
            message,
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        
        # Подготавливаем списки ID и имён
        rule_ids = [r[0] for r in rules_to_delete]
        rule_names = [r[1] for r in rules_to_delete]
        
        # Создаём прогресс-диалог (всегда показываем для множественного удаления)
        progress = QProgressDialog("Подготовка удаления...", "Отмена", 0, len(rules_to_delete), self)
        progress.setWindowTitle("Удаление правил")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)  # показываем сразу
        progress.show()
        
        # Создаём воркер
        self.delete_worker = DeleteRulesWorker(rule_ids, rule_names)
        self.delete_worker.progress.connect(lambda val, name: self._on_delete_progress(progress, val, name))
        self.delete_worker.finished.connect(lambda ok, err, failed: self._on_delete_finished(progress, ok, err, failed))
        self.delete_worker.error.connect(lambda msg: self._on_delete_error(msg))
        
        # Кнопка отмены в диалоге
        progress.canceled.connect(self.delete_worker.cancel)
        
        # Запускаем воркер
        self.delete_worker.start()
    
    def _on_delete_progress(self, progress_dialog, current_value, rule_name):
        """Обновление прогресс-диалога."""
        progress_dialog.setValue(current_value)
        progress_dialog.setLabelText(f"Удаление правила: {rule_name[:50]}...")
        QApplication.processEvents()
    
    def _on_delete_finished(self, progress_dialog, success_count, error_count, failed_rules):
        """Обработка завершения удаления."""
        progress_dialog.close()
        
        # Обновляем таблицу правил
        self.load_rules()
        
        # Показываем результат
        if error_count == 0:
            if success_count == 1:
                QMessageBox.information(self, "Успех", "Правило удалено")
            else:
                QMessageBox.information(self, "Успех", f"Удалено правил: {success_count}")
        else:
            if success_count > 0:
                msg = f"Удалено правил: {success_count}, не удалось удалить: {error_count}"
                if failed_rules:
                    failed_names = [f[1] for f in failed_rules[:5]]  # первые 5 имён
                    msg += f"\n\nНе удалённые правила: {', '.join(failed_names)}"
                    if len(failed_rules) > 5:
                        msg += f" и ещё {len(failed_rules) - 5}..."
                QMessageBox.warning(self, "Частичный успех", msg)
            else:
                QMessageBox.warning(self, "Ошибка", "Не удалось удалить ни одного правила")
    
    def _on_delete_error(self, error_message):
        """Обработка ошибки воркера."""
        logger.error(f"Ошибка воркера удаления: {error_message}")
        QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при удалении: {error_message}")

    def on_import_rules(self):
        """Импорт правил из JSON файла."""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл для импорта", "", "JSON файлы (*.json);;Все файлы (*)"
        )
        if not filepath:
            return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, list):
                QMessageBox.warning(self, "Ошибка", "Формат файла неверен: ожидается список правил.")
                return
            imported = 0
            errors = 0
            for item in data:
                try:
                    rule = FirewallRule.from_dict(item)
                    success = self.engine.add_rule(rule)
                    if success:
                        imported += 1
                    else:
                        errors += 1
                except Exception as e:
                    errors += 1
                    self.event_logger.error(EventType.IMPORT_EXPORT, f"Ошибка импорта правила: {e}")
            QMessageBox.information(
                self, "Импорт завершён",
                f"Импортировано правил: {imported}, ошибок: {errors}."
            )
            self.load_rules()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка импорта", f"Не удалось загрузить файл: {e}")

    def on_export_rules(self):
        """Экспорт правил в JSON файл."""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Выберите файл для экспорта", "firewall_rules.json", "JSON файлы (*.json);;Все файлы (*)"
        )
        if not filepath:
            return
        try:
            rules = self.engine.list_rules()
            data = [rule.to_dict() for rule in rules]
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Экспорт завершён", f"Экспортировано {len(rules)} правил.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось сохранить файл: {e}")

    def update_monitor_table(self):
        """Обновление таблицы мониторинга с применением фильтров."""
        try:
            connections = self.monitor.get_all_connections()
            
            # Применение фильтра по IP/подсети
            filter_text = self.monitor_filter_ip_edit.text().strip()
            filter_type = self.monitor_filter_type_combo.currentText()
            if filter_text:
                try:
                    # Пытаемся интерпретировать как подсеть
                    network = ipaddress.ip_network(filter_text, strict=False)
                    ip_filter = lambda ip: ipaddress.ip_address(ip) in network
                except ValueError:
                    # Иначе как одиночный IP
                    ip_filter = lambda ip: ip == filter_text
                
                filtered = []
                for conn in connections:
                    match = False
                    if filter_type in ("Любой", "Локальный адрес"):
                        if ip_filter(conn.local_addr):
                            match = True
                    if not match and filter_type in ("Любой", "Удалённый адрес"):
                        if ip_filter(conn.remote_addr):
                            match = True
                    if match:
                        filtered.append(conn)
                connections = filtered
            
            # Сортировка по времени (новые сверху)
            connections.sort(key=lambda c: c.timestamp, reverse=True)
            
            self.monitor_table.setRowCount(len(connections))
            for row, conn in enumerate(connections):
                self.monitor_table.setItem(row, 0, QTableWidgetItem(conn.protocol))
                self.monitor_table.setItem(row, 1, QTableWidgetItem(conn.local_addr))
                self.monitor_table.setItem(row, 2, QTableWidgetItem(str(conn.local_port)))
                self.monitor_table.setItem(row, 3, QTableWidgetItem(conn.remote_addr))
                self.monitor_table.setItem(row, 4, QTableWidgetItem(str(conn.remote_port)))
                self.monitor_table.setItem(row, 5, QTableWidgetItem(conn.state))
                self.monitor_table.setItem(row, 6, QTableWidgetItem(conn.process_name))
                self.monitor_table.setItem(row, 7, QTableWidgetItem(str(conn.pid)))
            self.monitor_status.setText(f"Подключений: {len(connections)} (отфильтровано {len(connections)})")
            # Кол-во подключений уже показывается в отдельной метке monitor_status,
            # поэтому не пишем его в статусбар, чтобы не затирать надпись "Трафик".
        except Exception as e:
            QMessageBox.warning(self, "Ошибка мониторинга", f"Не удалось обновить данные: {e}")

    def clear_monitor_cache(self):
        """Очистка кэша процессов монитора."""
        # Получаем текущее количество записей в кэше
        cache_size_before = len(self.monitor._process_cache)
        self.monitor.clear_cache()
        cache_size_after = len(self.monitor._process_cache)
        
        # Визуальная обратная связь: очищаем таблицу, чтобы показать обновление
        self.monitor_table.setRowCount(0)
        QApplication.processEvents()
        
        # Обновляем таблицу с небольшой задержкой для заметности
        from PySide6.QtCore import QTimer
        QTimer.singleShot(150, self.update_monitor_table)
        
        # Усиленная обратная связь в статусной строке
        self.statusBar().showMessage(
            f"✅ Кэш процессов очищен. Удалено {cache_size_before - cache_size_after} записей. Таблица обновляется...",
            10000
        )
        # Временно меняем цвет статусной строки на зелёный
        self.statusBar().setStyleSheet("background-color: #d4edda; color: #155724;")
        QTimer.singleShot(3000, lambda: self.statusBar().setStyleSheet(""))
        
        # Диалог с подробностями
        QMessageBox.information(
            self,
            "Кэш очищен",
            f"Кэш имён процессов очищен.\n\n"
            f"Записей в кэше до очистки: {cache_size_before}\n"
            f"Записей после очистки: {cache_size_after}\n\n"
            f"Таблица мониторинга будет обновлена через мгновение."
        )

    def update_traffic_graph(self):
        """Обновление графика скорости трафика."""
        try:
            sent_rate, recv_rate = self.traffic_stats.update()
            timestamps, sent_rates, recv_rates = self.traffic_stats.get_history()
            if not timestamps:
                return
            self.graph_ax.clear()
            self.graph_ax.plot(timestamps, sent_rates, label="Исходящий", color='red', linewidth=1.5)
            self.graph_ax.plot(timestamps, recv_rates, label="Входящий", color='blue', linewidth=1.5)
            self.graph_ax.set_title("Скорость сетевого трафика")
            self.graph_ax.set_xlabel("Время (сек)")
            self.graph_ax.set_ylabel("Скорость (Байт/с)")
            self.graph_ax.grid(True)
            self.graph_ax.legend()
            self.graph_canvas.draw()
            # Обновить статусбар с текущими скоростями
            # Порядок: сначала входящий (↓), потом исходящий (↑)
            self.statusBar().showMessage(
                f"Трафик: ↓{_format_speed(recv_rate)} ↑{_format_speed(sent_rate)} "
                f"| Подключений: {self.monitor_table.rowCount()}"
            )
        except Exception as e:
            # Тихий сбой, чтобы не мешать работе
            logger.debug(f"Ошибка обновления графика: {e}")

    def clear_traffic_graph(self):
        """Очистить график и историю статистики."""
        self.traffic_stats.clear()
        self.graph_ax.clear()
        self.graph_ax.set_title("Скорость сетевого трафика")
        self.graph_ax.set_xlabel("Время (сек)")
        self.graph_ax.set_ylabel("Скорость (Байт/с)")
        self.graph_ax.grid(True)
        self.graph_ax.legend(["Исходящий", "Входящий"])
        self.graph_canvas.draw()
        QMessageBox.information(self, "График очищен", "История трафика очищена.")

    def update_logs_table(self):
        """Обновление таблицы логов с учётом фильтров."""
        try:
            # Получение фильтров
            level_text = self.log_level_combo.currentText()
            level = None if level_text == "Все" else EventLevel(level_text)
            type_text = self.log_type_combo.currentText()
            event_type = None if type_text == "Все" else EventType(type_text)
            search_text = self.log_search_edit.text().strip().lower()

            global_logger.info(
                EventType.MONITOR_UPDATE,
                f"Обновление таблицы логов, фильтры: level={level_text}, type={type_text}, search={search_text}"
            )

            entries = self.event_logger.get_entries(level=level, event_type=event_type, limit=1000)
            # Дополнительная фильтрация по тексту поиска
            if search_text:
                filtered = []
                for entry in entries:
                    if (search_text in entry.message.lower() or
                        (entry.details and search_text in str(entry.details).lower())):
                        filtered.append(entry)
                entries = filtered

            self.logs_table.setRowCount(len(entries))
            for row, entry in enumerate(entries):
                self.logs_table.setItem(row, 0, QTableWidgetItem(entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")))
                self.logs_table.setItem(row, 1, QTableWidgetItem(entry.level.value))
                self.logs_table.setItem(row, 2, QTableWidgetItem(entry.event_type.value))
                self.logs_table.setItem(row, 3, QTableWidgetItem(entry.message))
                self.logs_table.setItem(row, 4, QTableWidgetItem(entry.source))
                details = str(entry.details) if entry.details else ""
                self.logs_table.setItem(row, 5, QTableWidgetItem(details))
            self.logs_status.setText(f"Записей: {len(entries)}")
            global_logger.info(EventType.MONITOR_UPDATE, f"Таблица логов обновлена, показано {len(entries)} записей")
        except Exception as e:
            global_logger.error(EventType.ERROR, f"Ошибка обновления таблицы логов: {e}")
            QMessageBox.warning(self, "Ошибка логов", f"Не удалось обновить журнал: {e}")

    def clear_logs(self):
        """Очистка журнала событий."""
        reply = QMessageBox.question(
            self, "Подтверждение",
            "Очистить весь журнал событий?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.event_logger.clear()
            self.update_logs_table()
            QMessageBox.information(self, "Журнал очищен", "Все записи удалены.")

    def _toggle_logs_auto_refresh(self, state):
        """Включение/выключение автообновления таблицы логов."""
        if state == Qt.Checked:
            self.logs_timer.start(5000)
            global_logger.info(EventType.MONITOR_UPDATE, "Автообновление логов включено")
        else:
            self.logs_timer.stop()
            global_logger.info(EventType.MONITOR_UPDATE, "Автообновление логов выключено")

    # Метод apply_theme удалён, так как тема интерфейса не работает

    def on_create_backup(self):
        """Создание резервной копии правил брандмауэра, источников угроз и записей IP/доменов."""
        try:
            include_logs = self.include_logs_check.isChecked()
            # Собираем реальные данные из текущего состояния
            rules = [r.to_dict() for r in self.engine.list_rules()]
            feeds = [_feed_to_dict(f) for f in self.threat_manager.get_feeds(enabled_only=False)]
            entries = [_entry_to_dict(e) for e in self.threat_manager.get_entries()]
            backup_path = self.backup_manager.create_backup(
                rules=rules,
                feeds=feeds,
                entries=entries,
                include_logs=include_logs
            )
            QMessageBox.information(
                self,
                "Резервная копия создана",
                f"Резервная копия успешно создана:\n{backup_path}\n\n"
                f"Правил брандмауэра: {len(rules)}\n"
                f"Источников угроз: {len(feeds)}\n"
                f"Записей IP/доменов: {len(entries)}"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Ошибка создания резервной копии",
                f"Не удалось создать резервную копию: {e}"
            )

    def on_restore_backup(self):
        """Восстановление правил, источников угроз и записей IP/доменов из резервной копии."""
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите архив для восстановления",
            "",
            "ZIP архивы (*.zip);;Все файлы (*)"
        )
        if not filepath:
            return

        reply = QMessageBox.question(
            self,
            "Подтверждение восстановления",
            "Восстановление перезапишет текущие правила, списки угроз и записи IP/доменов. Продолжить?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        try:
            data = self.backup_manager.restore_backup(filepath)
            summary = self._apply_restored_data(data)
            QMessageBox.information(self, "Восстановление завершено", summary)
        except Exception as e:
            QMessageBox.critical(
                self,
                "Ошибка восстановления",
                f"Не удалось восстановить из резервной копии: {e}"
            )

    def _apply_restored_data(self, data: dict) -> str:
        """Применяет восстановленные данные (правила, источники, записи) к движку и менеджеру угроз."""
        rules = data.get("rules", [])
        feeds_data = data.get("feeds", [])
        entries_data = data.get("entries", [])

        # Восстанавливаем правила брандмауэра
        rules_added = 0
        rules_errors = 0
        for rule_dict in rules:
            try:
                if self.engine.add_rule(FirewallRule.from_dict(rule_dict)):
                    rules_added += 1
                else:
                    rules_errors += 1
            except Exception:
                rules_errors += 1

        # Восстанавливаем источники угроз (обновляем существующие или добавляем новые)
        feeds_added = 0
        for feed_data in feeds_data:
            try:
                feed = _feed_from_dict(feed_data)
                if self.threat_manager.get_feed_by_id(feed.id):
                    self.threat_manager.update_feed(feed)
                else:
                    self.threat_manager.add_feed(feed)
                feeds_added += 1
            except Exception:
                pass

        # Восстанавливаем записи IP/доменов (сначала очищаем старые)
        entries_added = 0
        if entries_data:
            try:
                self.threat_manager.delete_all_block_rules()
            except Exception:
                pass
            threat_entries = [_entry_from_dict(d) for d in entries_data]
            entries_added = self.threat_manager.add_entries_batch(threat_entries)

        # Обновляем интерфейс
        self.load_rules()
        self.load_feeds_table()
        self.load_threat_entries_table()

        return (
            f"Восстановление завершено.\n\n"
            f"Правил брандмауэра добавлено: {rules_added} (ошибок: {rules_errors})\n"
            f"Источников угроз: {feeds_added}\n"
            f"Записей IP/доменов: {entries_added}"
        )

    def on_manage_backups(self):
        """Управление существующими резервными копиями."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Управление резервными копиями")
        dialog.setMinimumSize(500, 400)

        layout = QVBoxLayout()

        # Список резервных копий
        list_widget = QListWidget()
        backups = self.backup_manager.list_backups()
        for backup in backups:
            item = QListWidgetItem(str(backup))
            item.setData(Qt.UserRole, str(backup))
            list_widget.addItem(item)

        layout.addWidget(QLabel("Доступные резервные копии:"))
        layout.addWidget(list_widget)

        # Кнопки
        button_layout = QHBoxLayout()
        delete_btn = QPushButton("Удалить выбранную")
        delete_btn.clicked.connect(lambda: self._delete_selected_backup(list_widget, dialog))
        button_layout.addWidget(delete_btn)

        restore_btn = QPushButton("Восстановить выбранную")
        restore_btn.clicked.connect(lambda: self._restore_selected_backup(list_widget, dialog))
        button_layout.addWidget(restore_btn)

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)
        dialog.setLayout(layout)
        dialog.exec()

    def _delete_selected_backup(self, list_widget, parent_dialog):
        """Удаление выбранной резервной копии."""
        selected = list_widget.currentItem()
        if not selected:
            QMessageBox.warning(parent_dialog, "Внимание", "Выберите резервную копию для удаления.")
            return
        path = selected.data(Qt.UserRole)
        reply = QMessageBox.question(
            parent_dialog,
            "Подтверждение удаления",
            f"Удалить резервную копию?\n{path}",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            success = self.backup_manager.delete_backup(path)
            if success:
                QMessageBox.information(parent_dialog, "Удалено", "Резервная копия удалена.")
                # Обновляем список
                list_widget.clear()
                backups = self.backup_manager.list_backups()
                for backup in backups:
                    item = QListWidgetItem(str(backup))
                    item.setData(Qt.UserRole, str(backup))
                    list_widget.addItem(item)
            else:
                QMessageBox.warning(parent_dialog, "Ошибка", "Не удалось удалить резервную копию.")

    def _restore_selected_backup(self, list_widget, parent_dialog):
        """Восстановление выбранной резервной копии."""
        selected = list_widget.currentItem()
        if not selected:
            QMessageBox.warning(parent_dialog, "Внимание", "Выберите резервную копию для восстановления.")
            return
        path = selected.data(Qt.UserRole)
        reply = QMessageBox.question(
            parent_dialog,
            "Подтверждение восстановления",
            f"Восстановить конфигурацию из резервной копии?\n{path}",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        try:
            data = self.backup_manager.restore_backup(path)
            summary = self._apply_restored_data(data)
            QMessageBox.information(parent_dialog, "Восстановление завершено", summary)
            parent_dialog.accept()
        except Exception as e:
            QMessageBox.critical(parent_dialog, "Ошибка восстановления", str(e))

    def load_feeds_table(self):
        """Загрузка источников угроз в таблицу."""
        try:
            feeds = self.threat_manager.get_feeds(enabled_only=False)
            self.feeds_table.setRowCount(len(feeds))
            for row, feed in enumerate(feeds):
                self.feeds_table.setItem(row, 0, QTableWidgetItem(feed.id))
                self.feeds_table.setItem(row, 1, QTableWidgetItem(feed.name))
                source = feed.url if feed.url else feed.file_path or ""
                self.feeds_table.setItem(row, 2, QTableWidgetItem(source))
                self.feeds_table.setItem(row, 3, QTableWidgetItem(feed.format.value))
                last_update = feed.last_update.strftime("%Y-%m-%d %H:%M") if feed.last_update else "никогда"
                self.feeds_table.setItem(row, 4, QTableWidgetItem(last_update))
                self.feeds_table.setItem(row, 5, QTableWidgetItem("Да" if feed.enabled else "Нет"))
            self.threat_status.setText(f"Источников: {len(feeds)}, записей: загрузка...")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить источники: {e}")

    def load_threat_entries_table(self,
                                  feed_id: Optional[str] = None,
                                  search_text: Optional[str] = None,
                                  threat_type: Optional[str] = None):
        """Загрузка записей угроз в таблицу (с учётом фильтров и ускоренной отрисовки)."""
        try:
            entries = self.threat_manager.get_entries(feed_id)

            # Фильтр по типу угрозы
            if threat_type and threat_type != "Все":
                entries = [e for e in entries if e.threat_type.value == threat_type]

            # Поиск по всем видимым полям
            if search_text:
                needle = search_text.strip().lower()
                if needle:
                    entries = [
                        e for e in entries
                        if needle in (e.ip or "").lower()
                        or needle in (e.domain or "").lower()
                        or needle in (e.cidr or "").lower()
                        or needle in e.threat_type.value.lower()
                        or needle in (e.id or "").lower()
                    ]

            # Маппинг feed_id -> имя для отображения
            feed_map = {}
            if entries:
                feed_ids = set(e.feed_id for e in entries)
                for fid in feed_ids:
                    feed = self.threat_manager.get_feed_by_id(fid)
                    feed_map[fid] = feed.name if feed else fid

            table = self.threat_entries_table
            # Отключаем перерисовку и сортировку во время массового заполнения
            table.setUpdatesEnabled(False)
            was_sorting = table.isSortingEnabled()
            table.setSortingEnabled(False)
            table.setRowCount(len(entries))
            for row, entry in enumerate(entries):
                if row % 500 == 0:
                    QApplication.processEvents()  # не даём окну замерзать при массовом заполнении
                table.setItem(row, 0, QTableWidgetItem(entry.id))
                table.setItem(row, 1, QTableWidgetItem(entry.ip or entry.domain or ""))
                table.setItem(row, 2, QTableWidgetItem(entry.threat_type.value))
                feed_name = feed_map.get(entry.feed_id, entry.feed_id)
                table.setItem(row, 3, QTableWidgetItem(feed_name))
                added = entry.first_seen.strftime("%Y-%m-%d %H:%M") if entry.first_seen else ""
                table.setItem(row, 4, QTableWidgetItem(added))
                table.setItem(row, 5, QTableWidgetItem(entry.cidr or ""))
            table.setSortingEnabled(was_sorting)
            table.setUpdatesEnabled(True)
            table.viewport().update()
            self.threat_status.setText(
                f"Источников: {self.feeds_table.rowCount()}, записей: {len(entries)}"
            )
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить записи угроз: {e}")

    def on_add_feed(self):
        """Добавление нового источника угроз."""
        from ui.threat_feed_dialog import ThreatFeedDialog
        dialog = ThreatFeedDialog(self)
        if dialog.exec():
            feed = dialog.get_feed()
            try:
                self.threat_manager.add_feed(feed)
                self.load_feeds_table()
                self.event_logger.info(
                    EventType.THREAT_FEED_ADDED,
                    f"Добавлен источник угроз: {feed.name}",
                    feed_id=feed.id, feed_name=feed.name
                )
                QMessageBox.information(self, "Успех", "Источник добавлен")
            except Exception as e:
                self.event_logger.error(
                    EventType.ERROR,
                    f"Ошибка добавления источника угроз: {e}",
                    feed_name=feed.name, error=str(e)
                )
                QMessageBox.critical(self, "Ошибка", f"Не удалось добавить источник: {e}")

    def on_edit_feed(self):
        """Редактирование выбранного источника."""
        selected = self.feeds_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Внимание", "Выберите источник для редактирования")
            return
        row = selected[0].row()
        feed_id = self.feeds_table.item(row, 0).text()
        feeds = self.threat_manager.get_feeds(enabled_only=False)
        feed = next((f for f in feeds if f.id == feed_id), None)
        if not feed:
            QMessageBox.warning(self, "Ошибка", "Источник не найден")
            return
        from ui.threat_feed_dialog import ThreatFeedDialog
        dialog = ThreatFeedDialog(self, feed)
        if dialog.exec():
            updated_feed = dialog.get_feed()
            try:
                success = self.threat_manager.update_feed(updated_feed)
                if success:
                    self.load_feeds_table()
                    self.event_logger.info(
                        EventType.THREAT_FEED_UPDATED,
                        f"Источник угроз обновлён: {updated_feed.name}",
                        feed_id=updated_feed.id, feed_name=updated_feed.name
                    )
                    QMessageBox.information(self, "Успех", "Источник обновлён")
                else:
                    QMessageBox.warning(self, "Ошибка", "Не удалось обновить источник")
            except Exception as e:
                self.event_logger.error(
                    EventType.ERROR,
                    f"Ошибка обновления источника угроз: {e}",
                    feed_name=updated_feed.name, error=str(e)
                )
                QMessageBox.critical(self, "Ошибка", f"Не удалось обновить источник: {e}")

    def on_delete_feed(self):
        """Удаление выбранного источника."""
        selected = self.feeds_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Внимание", "Выберите источник для удаления")
            return
        row = selected[0].row()
        feed_id = self.feeds_table.item(row, 0).text()
        feed_name = self.feeds_table.item(row, 1).text()
        reply = QMessageBox.question(
            self, "Подтверждение",
            f"Удалить источник '{feed_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                success = self.threat_manager.delete_feed(feed_id)
                if success:
                    self.load_feeds_table()
                    self.event_logger.info(
                        EventType.THREAT_FEED_DELETED,
                        f"Источник угроз удалён: {feed_name}",
                        feed_id=feed_id, feed_name=feed_name
                    )
                    QMessageBox.information(self, "Успех", "Источник удалён")
                else:
                    QMessageBox.warning(self, "Ошибка", "Не удалось удалить источник")
            except Exception as e:
                self.event_logger.error(
                    EventType.ERROR,
                    f"Ошибка удаления источника угроз: {e}",
                    feed_id=feed_id, error=str(e)
                )
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить источник: {e}")

    def on_refresh_feeds(self):
        """Обновление всех источников с прогресс-диалогом."""
        reply = QMessageBox.question(
            self, "Подтверждение",
            "Обновить все источники угроз? Это может занять некоторое время.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        # Получаем список источников для оценки общего количества
        feeds = self.threat_manager.get_feeds(enabled_only=True)
        total_feeds = len(feeds)
        if total_feeds == 0:
            QMessageBox.information(self, "Нет источников", "Нет включённых источников для обновления.")
            return

        # Создаём прогресс-диалог
        progress = QProgressDialog("Обновление источников угроз...", "Отмена", 0, total_feeds, self)
        progress.setWindowTitle("Обновление")
        progress.setWindowModality(Qt.WindowModal)
        progress.show()

        # Обратный вызов для обновления прогресса
        def progress_callback(current, total, feed_name):
            progress.setValue(current)
            if feed_name:
                progress.setLabelText(f"Обновление источника: {feed_name}")
            # Обработка событий UI, чтобы прогресс не зависал
            QApplication.processEvents()
            if progress.wasCanceled():
                raise InterruptedError("Пользователь отменил операцию")

        try:
            results = self.threat_manager.update_all_feeds(progress_callback)
            total_added = sum(v for v in results.values() if v > 0)
            errors = sum(1 for v in results.values() if v == -1)
            updated_feeds = sum(1 for v in results.values() if v != -1)
            total_feeds = len(results)

            # Обновляем таблицы, пока прогресс-диалог ещё открыт
            progress.setLabelText("Обновление интерфейса...")
            QApplication.processEvents()
            self.load_feeds_table()
            self.load_threat_entries_table()
            progress.close()

            # Получаем детали ошибок
            error_details = self.threat_manager.get_last_update_errors()
            
            # Формируем общее сообщение
            if errors == 0:
                msg = (f"Обновление завершено успешно.\n"
                       f"Обработано источников: {total_feeds}\n"
                       f"Успешно обновлено: {updated_feeds}\n"
                       f"Добавлено записей: {total_added}")
                QMessageBox.information(self, "Обновление завершено", msg)
            else:
                # Объединяем общую статистику и детали ошибок в одном диалоге
                error_lines = []
                for feed_id, error_msg in error_details.items():
                    feed = self.threat_manager.get_feed_by_id(feed_id)
                    feed_name = feed.name if feed else feed_id
                    error_lines.append(f"• {feed_name}: {error_msg}")
                error_text = "\n".join(error_lines)
                msg = (f"Обновление завершено с ошибками.\n"
                       f"Обработано источников: {total_feeds}\n"
                       f"Успешно обновлено: {updated_feeds}\n"
                       f"Ошибок: {errors}\n"
                       f"Добавлено записей: {total_added}\n\n"
                       f"Детали ошибок:\n{error_text}")
                QMessageBox.warning(self, "Обновление завершено с ошибками", msg)
        except InterruptedError:
            QMessageBox.information(self, "Обновление отменено", "Обновление источников было отменено пользователем.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить источники: {e}")

    def on_apply_threat_filter(self):
        """Применение фильтра к таблице записей угроз."""
        feed_filter = self.threat_feed_combo.currentText()
        feed_id = None if feed_filter == "Все источники" else feed_filter
        search = self.threat_search_edit.text().strip()
        threat_type = self.threat_type_combo.currentText()
        self.load_threat_entries_table(
            feed_id=feed_id,
            search_text=search if search else None,
            threat_type=threat_type if threat_type != "Все" else None,
        )

    def on_reset_threat_filter(self):
        """Сброс фильтров таблицы записей угроз."""
        self.threat_type_combo.setCurrentIndex(0)
        self.threat_feed_combo.setCurrentIndex(0)
        self.threat_search_edit.clear()
        self.load_threat_entries_table()

    def on_apply_threat_rules(self):
        """Применение правил блокировки (группировка или отдельные правила) с живым прогрессом."""
        from PySide6.QtWidgets import (
            QMessageBox, QDialog, QApplication, QPlainTextEdit,
            QProgressBar, QPushButton, QLabel, QVBoxLayout, QHBoxLayout,
        )
        from PySide6.QtCore import Qt

        # Диалог выбора метода
        reply = QMessageBox.question(
            self, "Выбор метода",
            "Создать правила блокировки для всех записей угроз.\n"
            f"Найдено записей: {len(self.threat_manager.get_entries())}\n\n"
            "Выберите метод:\n"
            "• Да - использовать группировку (рекомендуется для >100 записей)\n"
            "• Нет - создавать отдельные правила для каждой записи\n"
            "• Отмена - отменить операцию",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
        )
        if reply == QMessageBox.Cancel:
            return
        use_grouping = (reply == QMessageBox.Yes)

        entries = self.threat_manager.get_entries()
        if not entries:
            QMessageBox.information(self, "Нет данных", "Нет записей угроз для применения правил.")
            return

        # Исключённые сети из настроек
        excluded_nets = []
        for raw in (self.config_manager.get("excluded_ips", []) or []):
            try:
                excluded_nets.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue

        def is_excluded(entry) -> bool:
            """Проверяет, попадает ли запись угрозы в исключённые сети."""
            candidates = []
            if entry.ip:
                candidates.append(entry.ip)
            if entry.cidr:
                candidates.append(entry.cidr)
            candidates.extend(entry.resolved_ips or [])
            for cand in candidates:
                try:
                    addr = ipaddress.ip_address(cand.split("/")[0])
                except ValueError:
                    continue
                for net in excluded_nets:
                    if addr in net:
                        return True
            return False

        # Отсекаем записи, попавшие в список исключений
        entries = [e for e in entries if not is_excluded(e)]
        if not entries:
            QMessageBox.information(
                self, "Нет данных",
                "Все записи угроз попали в список исключений IP. Правила не создавались."
            )
            return

        # Существующие правила ThreatIntel — берём из кэша load_rules,
        # т.к. list_rules() выполняет медленный PowerShell и блокирует окно на несколько секунд.
        existing_names = set()
        for r in getattr(self, "_all_rules", []) or []:
            if r.name.startswith("ThreatIntel"):
                existing_names.add(r.name)

        # Диалог с логом и прогрессом
        dlg = QDialog(self)
        dlg.setWindowTitle("Применение правил блокировки")
        dlg.resize(640, 420)
        dlg.setWindowModality(Qt.WindowModal)
        dlg_layout = QVBoxLayout(dlg)
        title_lbl = QLabel("Применение правил блокировки...")
        dlg_layout.addWidget(title_lbl)

        log_view = QPlainTextEdit()
        log_view.setReadOnly(True)
        dlg_layout.addWidget(log_view, 1)

        progress = QProgressBar()
        progress.setRange(0, 100)
        progress.setValue(0)
        dlg_layout.addWidget(progress)
        dlg_layout.addWidget(QLabel("Операция может занять время. Не закрывайте окно до завершения."))

        def append_log(text):
            log_view.appendPlainText(text)
            scrollbar = log_view.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
            QApplication.processEvents()

        def update_progress(value):
            progress.setValue(max(0, min(100, int(value))))
            QApplication.processEvents()

        dlg.show()

        applied = 0
        skipped = 0
        skipped_existing = 0
        errors = 0

        def on_rule_added(rule_name):
            nonlocal applied
            applied += 1
            append_log(f"Добавлено правило: {rule_name}")

        if use_grouping:
            # Подготовка: резолвим домены и распределяем записи по источникам
            resolved_entries = []
            total = len(entries)
            for i, entry in enumerate(entries):
                update_progress(i / max(total, 1) * 20)  # фаза подготовки: 0..20%
                if not entry.ip and not entry.cidr and not entry.domain:
                    skipped += 1
                    continue
                if entry.domain and not entry.resolved_ips:
                    try:
                        resolved = self.domain_resolver.resolve(entry.domain)
                        if resolved:
                            entry.resolved_ips = resolved
                        else:
                            skipped += 1
                            continue
                    except Exception as e:
                        logger.error(f"Ошибка резолвинга домена {entry.domain}: {e}")
                        errors += 1
                        continue
                resolved_entries.append(entry)
                QApplication.processEvents()

            from collections import defaultdict
            entries_by_feed = defaultdict(list)
            for entry in resolved_entries:
                entries_by_feed[entry.feed_id].append(entry)

            update_progress(25)
            for feed_id, feed_entries in entries_by_feed.items():
                feed = self.threat_manager.get_feed_by_id(feed_id)
                if not feed:
                    skipped += len(feed_entries)
                    continue
                try:
                    _ok, _sk = self.rule_generator.apply_grouped_rules(
                        feed_entries, feed,
                        existing_names=existing_names,
                        on_rule_added=on_rule_added,
                    )
                    skipped_existing += _sk
                except Exception as e:
                    logger.error(f"Ошибка применения группированных правил для источника {feed.name}: {e}")
                    errors += len(feed_entries)
                append_log(f"Источник «{feed.name}» обработан")
                QApplication.processEvents()

            # Обновляем таблицы, пока диалог ещё открыт
            update_progress(95)
            try:
                self.load_rules()
            except Exception:
                pass
            update_progress(100)
            dlg.accept()
            msg = (f"Применение правил завершено.\n"
                   f"Создано новых правил: {applied}\n"
                   f"Уже существовало (пропущено): {skipped_existing}\n"
                   f"Пропущено записей без адреса: {skipped}\n"
                   f"Ошибок: {errors}")
            QMessageBox.information(self, "Результат", msg)
            logger.info(f"Группированные правила: applied={applied}, skipped={skipped}, errors={errors}")
        else:
            # Отдельные правила для каждой записи
            total = len(entries)
            for i, entry in enumerate(entries):
                update_progress(i / max(total, 1) * 90)  # основная фаза: 0..90%
                feed = self.threat_manager.get_feed_by_id(entry.feed_id)
                if not feed:
                    skipped += 1
                    continue
                if not entry.ip and not entry.cidr and not entry.domain:
                    skipped += 1
                    continue
                if entry.domain and not entry.resolved_ips:
                    try:
                        resolved = self.domain_resolver.resolve(entry.domain)
                        if resolved:
                            entry.resolved_ips = resolved
                        else:
                            skipped += 1
                            continue
                    except Exception as e:
                        logger.error(f"Ошибка резолвинга домена {entry.domain}: {e}")
                        errors += 1
                        continue
                try:
                    success, _sk = self.rule_generator.apply_entry(
                        entry, feed,
                        existing_names=existing_names,
                        on_rule_added=on_rule_added,
                    )
                    skipped_existing += _sk
                    if not success and _sk == 0:
                        skipped += 1
                except Exception as e:
                    logger.error(f"Ошибка применения правила для записи {entry.id}: {e}")
                    errors += 1
                QApplication.processEvents()

            # Обновляем таблицы, пока диалог ещё открыт
            update_progress(95)
            try:
                self.load_rules()
            except Exception:
                pass
            update_progress(100)
            dlg.accept()
            msg = (f"Применение правил завершено.\n"
                   f"Создано новых правил: {applied}\n"
                   f"Уже существовало (пропущено): {skipped_existing}\n"
                   f"Пропущено записей без адреса: {skipped}\n"
                   f"Ошибок: {errors}")
            QMessageBox.information(self, "Результат", msg)
            logger.info(f"Индивидуальные правила: applied={applied}, skipped={skipped}, errors={errors}")

    def on_clear_dns_cache(self):
        """Очистка кэша DNS."""
        try:
            import subprocess
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, shell=True)
            QMessageBox.information(self, "Кэш очищен", "DNS кэш очищен.")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось очистить DNS кэш: {e}")

    def on_delete_all_threat_rules(self):
        """Удаление всех правил блокировки угроз из базы данных и Windows Firewall."""
        reply = QMessageBox.question(
            self,
            "Подтверждение удаления",
            "Вы уверены, что хотите удалить все правила блокировки угроз?\n\n"
            "Это действие очистит таблицы block_rules и threat_entries (все записи угроз),\n"
            "а также удалит соответствующие правила из Windows Firewall.\n\n"
            "⚠️ Процедура может занять несколько минут в зависимости от количества правил.\n"
            "Продолжить?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        try:
            # Создаём прогресс-диалог
            progress = QProgressDialog("Поиск и удаление правил блокировки угроз...", "Отмена", 0, 100, self)
            progress.setWindowTitle("Удаление правил угроз")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(0)
            progress.show()
            QApplication.processEvents()
            
            # 1. Создаём быстрый удалитель правил
            deleter = FastRuleDeleter(self.engine)
            
            # 2. Удаляем правила из Windows Firewall со словом "ThreatIntel" в имени
            progress.setLabelText("Поиск правил с префиксом 'ThreatIntel'...")
            progress.setValue(10)
            QApplication.processEvents()
            
            logger.info("Начинаем удаление всех правил блокировки угроз (быстрый метод)")
            firewall_result = deleter.delete_by_prefix("ThreatIntel", method="auto")
            
            progress.setLabelText(f"Удалено {firewall_result.get('deleted', 0)} правил из Windows Firewall...")
            progress.setValue(50)
            QApplication.processEvents()
            
            # 2.1. Добиваем оставшиеся правила ThreatIntel, если какой-то метод не справился
            extra_deleted = 0
            try:
                remaining = [r for r in self.engine.list_rules() if r.name.startswith("ThreatIntel")]
                for r in remaining:
                    if self.engine.delete_rule(r.id, display_name=r.name):
                        extra_deleted += 1
                if extra_deleted:
                    logger.info(f"Добор: удалено ещё {extra_deleted} правил ThreatIntel")
            except Exception as e:
                logger.error(f"Ошибка добора правил ThreatIntel: {e}")
            
            # 3. Удалить записи из базы данных (threat_entries и block_rules)
            progress.setLabelText("Очистка базы данных угроз...")
            progress.setValue(70)
            QApplication.processEvents()
            
            db_deleted = self.threat_manager.delete_all_block_rules()
            
            # 4. Обновить UI таблиц
            progress.setLabelText("Обновление интерфейса...")
            progress.setValue(90)
            QApplication.processEvents()
            
            self.load_feeds_table()
            self.load_threat_entries_table()
            # Обновляем таблицу правил на вкладке "Правила"
            self.load_rules()
            
            progress.setValue(100)
            progress.close()
            
            # 5. Показать результат
            total_found = firewall_result.get('total_found', 0)
            firewall_deleted = firewall_result.get('deleted', 0)
            errors = firewall_result.get('errors', 0)
            method_used = firewall_result.get('method_used', 'unknown')
            
            msg_lines = [
                f"Удаление завершено.",
                f"Найдено правил 'ThreatIntel*': {total_found}",
                f"Удалено правил из Windows Firewall: {firewall_deleted}",
                f"Дополнительно удалено: {extra_deleted}",
                f"Ошибок при удалении: {errors}",
                f"Использованный метод: {method_used}",
                f"Удалено записей из базы данных: {db_deleted}"
            ]
            
            if errors > 0:
                msg_lines.append(f"\n⚠️ Не удалось удалить {errors} правил. Возможно, недостаточно прав или правила защищены.")
            elif total_found == 0:
                msg_lines.append("\nℹ️ Правил с префиксом 'ThreatIntel:' не найдено.")
            elif firewall_deleted < total_found:
                msg_lines.append(f"\n⚠️ Удалено только {firewall_deleted} из {total_found} правил. Остальные могли быть удалены ранее.")
            
            msg = "\n".join(msg_lines)
            QMessageBox.information(
                self,
                "Удаление завершено",
                msg
            )
            logger.info(f"Пользователь удалил все правила блокировки угроз: найдено {total_found}, удалено {firewall_deleted}, ошибок {errors}, записей БД {db_deleted}.")
            
        except Exception as e:
            # Закрываем прогресс-диалог в случае ошибки
            try:
                progress.close()
            except:
                pass
                
            QMessageBox.critical(
                self,
                "Ошибка",
                f"Не удалось удалить правила блокировки угроз: {e}"
            )
            logger.error(f"Ошибка удаления всех правил блокировки угроз: {e}", exc_info=True)

    def closeEvent(self, event):
        """Обработчик закрытия окна."""
        # Сохраняем настройки перед закрытием
        self.config_manager.save()
        logger.info("Закрытие приложения.")
        event.accept()
        QApplication.quit()


def main():
    """Точка входа для UI."""
    app = QApplication(sys.argv)
    app.setApplicationName("BlocklistFW")
    app.setQuitOnLastWindowClosed(True)

    # Иконка приложения
    icon_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "resources", "icons", "app_icon.ico",
    )
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    # Проверка статуса брандмауэра Windows при запуске
    if not check_firewall_on_startup():
        # Пользователь выбрал "Закрыть"
        sys.exit(0)

    window = MainWindow()
    window.show()

    # Проверка, что окно не выходит за границы экрана
    from PySide6.QtGui import QScreen
    screen = app.primaryScreen()
    if screen:
        available = screen.availableGeometry()
        # Получаем текущую геометрию окна
        geo = window.frameGeometry()
        # Корректируем позицию, если окно выходит за границы
        if geo.right() > available.right():
            geo.moveRight(available.right())
        if geo.bottom() > available.bottom():
            geo.moveBottom(available.bottom())
        if geo.left() < available.left():
            geo.moveLeft(available.left())
        if geo.top() < available.top():
            geo.moveTop(available.top())
        window.move(geo.topLeft())

    sys.exit(app.exec())


if __name__ == "__main__":
    main()