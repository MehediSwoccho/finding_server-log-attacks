from __future__ import annotations


_TEXT_CONTROL_BYTES = frozenset((9, 10, 12, 13, 27))


def looks_binary(sample: bytes) -> bool:
    """Detect common binary signatures/control-heavy samples without buffering a full upload."""
    if b"\x00" in sample:
        return True
    controls = sum(byte < 32 and byte not in _TEXT_CONTROL_BYTES for byte in sample)
    return controls > max(2, len(sample) // 20)
