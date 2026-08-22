"""
Сбор статистики сетевого трафика для построения графиков.
"""
import psutil
import time
from collections import deque
from typing import Tuple, List


class TrafficStats:
    """
    Сбор и хранение статистики сетевого трафика.
    """
    def __init__(self, max_history: int = 60):
        """
        :param max_history: максимальное количество точек истории (по умолчанию 60, т.е. 1 минута при обновлении раз в секунду)
        """
        self.max_history = max_history
        self.history_timestamps = deque(maxlen=max_history)
        self.history_bytes_sent = deque(maxlen=max_history)
        self.history_bytes_recv = deque(maxlen=max_history)
        self.last_bytes_sent = 0
        self.last_bytes_recv = 0
        self.last_time = time.time()
        self._init_counters()

    def _init_counters(self):
        """Инициализация начальных значений счётчиков."""
        net_io = psutil.net_io_counters()
        self.last_bytes_sent = net_io.bytes_sent
        self.last_bytes_recv = net_io.bytes_recv
        self.last_time = time.time()

    def update(self) -> Tuple[float, float]:
        """
        Обновить статистику, вычислив скорость отправки/приёма за прошедший интервал.
        Возвращает кортеж (sent_rate_bps, recv_rate_bps) - скорость в байтах в секунду.
        """
        now = time.time()
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv

        dt = now - self.last_time
        if dt <= 0:
            dt = 1e-3

        sent_rate = (bytes_sent - self.last_bytes_sent) / dt  # байт/сек
        recv_rate = (bytes_recv - self.last_bytes_recv) / dt

        # Сохраняем историю
        self.history_timestamps.append(now)
        self.history_bytes_sent.append(sent_rate)
        self.history_bytes_recv.append(recv_rate)

        # Обновляем последние значения
        self.last_bytes_sent = bytes_sent
        self.last_bytes_recv = bytes_recv
        self.last_time = now

        return sent_rate, recv_rate

    def get_history(self) -> Tuple[List[float], List[float], List[float]]:
        """
        Возвращает историю для построения графика.
        Возвращает (timestamps, sent_rates, recv_rates).
        timestamps - секунды относительно текущего времени.
        """
        if not self.history_timestamps:
            return [], [], []
        now = time.time()
        timestamps = [ts - now for ts in self.history_timestamps]  # отрицательные значения (прошлое)
        return list(timestamps), list(self.history_bytes_sent), list(self.history_bytes_recv)

    def clear(self):
        """Очистить историю."""
        self.history_timestamps.clear()
        self.history_bytes_sent.clear()
        self.history_bytes_recv.clear()
        self._init_counters()


if __name__ == "__main__":
    # Простой тест
    stats = TrafficStats(max_history=5)
    for i in range(10):
        sent, recv = stats.update()
        # печать(f"Обновление {i}: отправлено={sent:.0f} Б/с, принято={recv:.0f} Б/с")
        time.sleep(0.5)
    # печать("Временные метки истории:", stats.history_timestamps)
    # печать("История отправленных:", stats.history_bytes_sent)
    # печать("История принятых:", stats.history_bytes_recv)