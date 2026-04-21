"""
Generador de keystream MFSU — fractalyx.crypto.keystream

Arquitectura de defensa en profundidad:

    CAPA 1 — Campo fractal (fuente de entropía):
        ψ₀ derivado de (enc_key ‖ iv) → SHA3-512.
        Se evoluciona KS_N puntos durante n_steps pasos.
        Se extraen Re(ψ) e Im(ψ) como bytes brutos.

    CAPA 2 — SHA3-256 whitener (uniformidad formal):
        bytes_fractal ⊕ SHA3-256(mixer_key, counter).
        Rol: garantizar distribución uniforme de bytes.

Cada capa tiene un rol diferente y demostrado por tests:
    Campo fractal solo  → χ²=1752, p≈0   (NO uniforme por sí solo)
    Campo + SHA3 whitener → χ²=254, p=0.49 (uniforme — pasa test)
"""

from __future__ import annotations

import hashlib

import numpy as np

from fractalyx.core import KS_N, step_mfsu


def generate(enc_key: bytes, iv: bytes, length: int) -> np.ndarray:
    """
    Genera ``length`` bytes de keystream determinista a partir de (enc_key, iv).

    El keystream es pseudoaleatorio: idéntico para los mismos (enc_key, iv),
    completamente distinto para cualquier cambio de un bit en alguno de ellos.

    Args:
        enc_key: Clave de cifrado de 64 bytes (primeros 64 B del KDF).
        iv:      Vector de inicialización de 16 bytes, único por cifrado.
        length:  Longitud del keystream a generar en bytes.

    Returns:
        Array numpy de dtype uint8 con ``length`` bytes de keystream.

    Raises:
        ValueError: Si enc_key o iv tienen longitud incorrecta.
    """
    if len(enc_key) < 32:
        raise ValueError("enc_key debe tener al menos 32 bytes")
    if len(iv) < 8:
        raise ValueError("iv debe tener al menos 8 bytes")

    h = hashlib.sha3_512(enc_key + iv).digest()

    # n_steps variable entre 48 y 112 — derivado de la clave para evitar
    # ataques de ajuste de complejidad (el atacante no controla los pasos)
    n_steps = 48 + (h[0] % 64)

    rng = np.random.default_rng(np.frombuffer(h[:32], dtype=np.uint32))
    psi: np.ndarray = rng.standard_normal(KS_N) + 1j * rng.standard_normal(KS_N)

    # Modular la amplitud inicial con el hash completo — más sensibilidad
    scale = np.frombuffer(h[:64], dtype=np.uint8).astype(float) / 255.0
    psi[:64] *= scale + 0.5

    # Clave del whitener: derivada independientemente de enc_key
    mixer_key = hashlib.sha3_256(enc_key[32:64] + iv).digest()

    # ── Capa 1: evolucionar el campo y acumular bytes brutos ──────────────
    raw_buf: list[int] = []
    for step in range(n_steps):
        psi = step_mfsu(psi, h, step, dt=0.01)
        re_b = (np.real(psi) * 1e4).astype(np.int64) & 0xFF
        im_b = (np.imag(psi) * 1e4).astype(np.int64) & 0xFF
        raw_buf.extend(re_b.tolist())
        raw_buf.extend(im_b.tolist())
        if len(raw_buf) >= length * 2:
            break

    raw = np.array(raw_buf[:length], dtype=np.uint8)

    # ── Capa 2: SHA3-256 whitener — uniformidad formal ────────────────────
    mixed = bytearray(length)
    block_counter = 0
    for i in range(0, length, 32):
        block_key = hashlib.sha3_256(
            mixer_key + block_counter.to_bytes(4, "big")
        ).digest()
        block_counter += 1
        chunk = raw[i : i + 32]
        for j, (rb, kb) in enumerate(zip(chunk, block_key)):
            if i + j < length:
                mixed[i + j] = rb ^ kb

    return np.frombuffer(bytes(mixed), dtype=np.uint8)
