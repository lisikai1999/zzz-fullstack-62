from difflib import unified_diff
from dataclasses import dataclass
from typing import Optional


@dataclass
class DiffResult:
    match: bool
    diff_text: Optional[str]
    original_length: int
    actual_length: int
    similarity: float

    def to_dict(self) -> dict:
        return {
            "match": self.match,
            "diff_text": self.diff_text,
            "original_length": self.original_length,
            "actual_length": self.actual_length,
            "similarity_percent": round(self.similarity * 100, 2),
        }


class ResponseComparator:
    def compare(self, original: bytes, actual: bytes) -> DiffResult:
        if original == actual:
            return DiffResult(
                match=True, diff_text=None,
                original_length=len(original),
                actual_length=len(actual),
                similarity=1.0,
            )

        try:
            orig_text = original.decode('utf-8', errors='replace')
            actual_text = actual.decode('utf-8', errors='replace')

            orig_lines = orig_text.splitlines(keepends=True)
            actual_lines = actual_text.splitlines(keepends=True)

            diff = list(unified_diff(
                orig_lines, actual_lines,
                fromfile='original', tofile='replayed',
                lineterm='',
            ))

            similarity = self._compute_similarity(orig_lines, actual_lines)

            return DiffResult(
                match=False,
                diff_text=''.join(diff) if diff else None,
                original_length=len(original),
                actual_length=len(actual),
                similarity=similarity,
            )
        except Exception:
            return DiffResult(
                match=False,
                diff_text=f"Binary: original={len(original)}B, actual={len(actual)}B",
                original_length=len(original),
                actual_length=len(actual),
                similarity=0.0,
            )

    @staticmethod
    def _compute_similarity(orig_lines: list, actual_lines: list) -> float:
        if not orig_lines and not actual_lines:
            return 1.0
        total = max(len(orig_lines), len(actual_lines))
        if total == 0:
            return 1.0
        matches = sum(1 for a, b in zip(orig_lines, actual_lines) if a == b)
        return matches / total
