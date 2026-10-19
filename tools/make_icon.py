"""
make_icon.py — Gera assets/app.ico (escudo com fechadura) sem dependências externas.

Uso:  python tools/make_icon.py
"""
from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

SIZES = (16, 24, 32, 48, 64, 128, 256)
SUPERSAMPLE = 4
TOP, BOTTOM, MID = 0.07, 0.95, 0.52   # limites verticais do escudo
HALF_W, CORNER = 0.36, 0.08


def _in_shield(x: float, y: float, scale: float = 1.0) -> bool:
    # Escala em torno do centro para obter a borda interna.
    x = 0.5 + (x - 0.5) / scale
    y = 0.5 + (y - 0.5) / scale
    if y < TOP or y > BOTTOM:
        return False
    dx = abs(x - 0.5)
    if y <= MID:
        if dx > HALF_W:
            return False
        # cantos superiores arredondados
        cx, cy = HALF_W - CORNER, TOP + CORNER
        if dx > cx and y < cy:
            return (dx - cx) ** 2 + (y - cy) ** 2 <= CORNER ** 2
        return True
    t = (y - MID) / (BOTTOM - MID)
    return dx <= HALF_W * math.cos(t * math.pi / 2) ** 0.75


def _in_keyhole(x: float, y: float) -> bool:
    if (x - 0.5) ** 2 + (y - 0.42) ** 2 <= 0.105 ** 2:
        return True
    if 0.44 <= y <= 0.70:
        t = (y - 0.44) / 0.26
        return abs(x - 0.5) <= 0.042 + 0.035 * t
    return False


def _color(x: float, y: float, size: int) -> tuple[float, float, float, float] | None:
    if not _in_shield(x, y):
        return None
    if _in_keyhole(x, y):
        return (1.0, 1.0, 1.0, 1.0)
    border = 0.90 if size >= 32 else 0.84
    if not _in_shield(x, y, border):
        return (0.08, 0.22, 0.42, 1.0)          # contorno azul-escuro
    g = (y - TOP) / (BOTTOM - TOP)             # degradê vertical
    return (0.16 + 0.08 * g, 0.47 - 0.16 * g, 0.78 - 0.22 * g, 1.0)


def render(size: int) -> bytes:
    rows = []
    n = SUPERSAMPLE
    for py in range(size):
        row = bytearray([0])                   # filtro PNG "None"
        for px in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(n):
                for sx in range(n):
                    c = _color((px + (sx + 0.5) / n) / size, (py + (sy + 0.5) / n) / size, size)
                    if c:
                        for i in range(3):
                            acc[i] += c[i] * c[3]
                        acc[3] += c[3]
            a = acc[3] / (n * n)
            rgb = [acc[i] / acc[3] if acc[3] else 0 for i in range(3)]
            row += bytes(round(v * 255) for v in (*rgb, a))
        rows.append(bytes(row))
    return _png(size, b"".join(rows))


def _png(size: int, raw: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # RGBA 8 bits
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def build_ico(path: Path) -> None:
    images = [render(s) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries, blobs = b"", b""
    for size, png in zip(SIZES, images):
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        offset += len(png)
        blobs += png
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + entries + blobs)
    (path.parent / "app.png").write_bytes(images[-1])   # prévia em 256 px


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "assets" / "app.ico"
    build_ico(out)
    print(f"Ícone gerado: {out}")
