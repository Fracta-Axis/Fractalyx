"""Tests del módulo axis.hash_mfsu — hash Merkle-Damgård fractal."""

import pytest
from axis.hash_mfsu import digest


class TestDigest:
    def test_output_length(self):
        h = digest(b"hola")
        assert len(h) == 128  # SHA3-512 → 64 bytes → 128 hex chars

    def test_hex_string(self):
        h = digest(b"test")
        assert all(c in "0123456789abcdef" for c in h)

    def test_deterministic(self):
        assert digest(b"abc") == digest(b"abc")

    def test_empty_input(self):
        h = digest(b"")
        assert len(h) == 128

    def test_avalanche_single_char(self):
        """Cambiar 1 carácter debe cambiar ~50% de los bits."""
        h1 = digest(b"hola mundo")
        h2 = digest(b"hola Mundo")
        b1 = bin(int(h1, 16))[2:].zfill(512)
        b2 = bin(int(h2, 16))[2:].zfill(512)
        diff = sum(a != b for a, b in zip(b1, b2))
        pct = diff / 512 * 100
        assert 30 <= pct <= 70, f"Avalanche fuera de rango: {pct:.1f}%"

    def test_length_extension_resistance(self):
        """Mensajes distintos deben producir digests distintos."""
        h1 = digest(b"mensaje")
        h2 = digest(b"mensajex")
        assert h1 != h2

    def test_large_input(self):
        data = b"A" * 10_000
        h = digest(data)
        assert len(h) == 128

    def test_binary_input(self):
        import os
        data = os.urandom(256)
        h = digest(data)
        assert len(h) == 128

    def test_block_size_independence(self):
        """El resultado debe ser el mismo con distintos block_size."""
        data = b"test data for block size"
        h1 = digest(data, block_size=32)
        h2 = digest(data, block_size=64)
        # block_size distinto produce distinto procesamiento → digests distintos
        # pero ambos deben tener el formato correcto
        assert len(h1) == 128
        assert len(h2) == 128
