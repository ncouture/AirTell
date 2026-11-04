from __future__ import annotations

from collections import deque
import math
import statistics


class BaselineTracker:
    """
    Tracks dynamic idle baseline RSSI for each (rx_id, tx_mac, channel) link using
    Exponential Moving Average (EMA) and Hampel/median outlier rejection.
    """
    def __init__(self, alpha: float = 0.02, outlier_threshold: float = 12.0, history_size: int = 5):
        self.alpha = alpha
        self.outlier_threshold = outlier_threshold
        self.history_size = history_size
        self.baselines: dict[tuple[str, str, int], float] = {}
        self.variances: dict[tuple[str, str, int], float] = {}
        self.history: dict[tuple[str, str, int], deque[float]] = {}

    def update(self, rx_id: str, tx_mac: str, rssi: float, channel: int = 37) -> float:
        key = (rx_id, tx_mac, channel)

        if key not in self.history:
            self.history[key] = deque(maxlen=self.history_size)

        # Outlier rejection using median window
        hist = self.history[key]
        if len(hist) >= 3:
            median_val = float(statistics.median(hist))
            if abs(rssi - median_val) > self.outlier_threshold:
                return self.baselines.get(key, median_val)

        hist.append(rssi)

        # EMA update
        if key not in self.baselines:
            self.baselines[key] = rssi
            self.variances[key] = 1.0
        else:
            delta = rssi - self.baselines[key]
            self.baselines[key] = self.alpha * rssi + (1.0 - self.alpha) * self.baselines[key]
            self.variances[key] = (1.0 - self.alpha) * self.variances[key] + self.alpha * (delta ** 2)

        return self.baselines[key]

    def get_baseline(self, rx_id: str, tx_mac: str, channel: int = 37, default: float = -60.0) -> float:
        return self.baselines.get((rx_id, tx_mac, channel), default)

    def get_std_dev(self, rx_id: str, tx_mac: str, channel: int = 37, min_std: float = 1.0) -> float:
        var = self.variances.get((rx_id, tx_mac, channel), min_std ** 2)
        return float(math.sqrt(max(min_std ** 2, var)))

