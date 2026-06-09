from dataclasses import dataclass
from typing import List


@dataclass
class TimedSegment:
    index: int
    timestamp: float
    data: bytes


class TimingController:
    def __init__(self, segments: List[TimedSegment], speed_factor: float = 1.0):
        self.segments = sorted(segments, key=lambda s: s.timestamp)
        self.speed_factor = speed_factor
        self._delays: List[float] = []
        self._compute_delays()

    def _compute_delays(self):
        self._delays = [0.0]
        for i in range(1, len(self.segments)):
            delta = self.segments[i].timestamp - self.segments[i - 1].timestamp
            adjusted = delta / self.speed_factor if self.speed_factor > 0 else 0
            self._delays.append(max(0, adjusted))

    def get_delay(self, index: int) -> float:
        if index < len(self._delays):
            return self._delays[index]
        return 0.0

    @property
    def total_segments(self) -> int:
        return len(self.segments)
