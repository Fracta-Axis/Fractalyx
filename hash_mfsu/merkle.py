"""
Hash Merkle-Damgård Fractal — fractalyx.hash_mfsu.merkle

El mensaje alimenta el campo ψ(x,t) directamente en cada bloque, no
solo en la condición inicial. Esto significa que cambiar cualquier bloque
altera toda la trayectoria posterior del campo.

Proceso por bloque mᵢ:
    ψ = ψ + δF · encode(mᵢ)    ← el bloque perturba el campo
    ψ = evolve(ψ, 16 pasos)     ← la SPDE mezcla la perturbación

Digest final:
    SHA3-512(estado_final)       ← uniformidad formal garantizada

El IV fractal es fijo y público (no es secreto): define el punto de
partida del campo antes de procesar el primer bloque del mensaje.
"""

from __future__ import annotations

import hashlib
import struct

import numpy as np

from fractalyx.core import DELTA_F, step_mfsu


# IV fractal público — fijo para reproducibilidad entre versiones
_IV_FRACTAL_SEED = b"MFSU_HASH_IV_v3_DELTA_F_0921"
_HASH_N = 256       # puntos del campo para el hash
_HASH_STEPS = 16    # pasos de evolución por bloque
_HASH_DT = 0.005    # paso temporal para el hash


def _initial_field() -> np.ndarray:
    """Genera el campo inicial a partir del IV fractal fijo."""
    h_iv = hashlib.sha3_512(hashlib.sha3_256(_IV_FRACTAL_SEED).digest()).digest()
    rng = np.random.default_rng(np.frombuffer(h_iv[:32], dtype=np.uint32))
    return rng.standard_normal(_HASH_N) + 1j * rng.standard_normal(_HASH_N)


def digest(data: bytes, block_size: int = 64) -> str:
    """
    Calcula el hash MFSU-MDF de ``data`` y devuelve el hex digest (128 chars).

    El padding sigue el esquema Merkle-Damgård clásico:
        data ‖ 0x80 ‖ 0x00... ‖ len(data) como uint64 big-endian

    Args:
        data:       Datos a hashear (cualquier longitud, incluyendo b"").
        block_size: Tamaño de bloque para el procesamiento (default 64 bytes).

    Returns:
        Hex string de 128 caracteres (SHA3-512 del estado final del campo).
    """
    psi = _initial_field()

    # Padding Merkle-Damgård
    padded = data + b"\x80"
    while len(padded) % block_size != 0:
        padded += b"\x00"
    padded += struct.pack(">Q", len(data))
    while len(padded) % block_size != 0:
        padded += b"\x00"

    block_num = 0
    for i in range(0, len(padded), block_size):
        block = padded[i : i + block_size]

        # Codificar bloque como perturbación real del campo
        block_vals = np.frombuffer(block, dtype=np.uint8).astype(float) / 255.0
        indices = np.linspace(0, len(block_vals) - 1, _HASH_N)
        block_interp = np.interp(indices, np.arange(len(block_vals)), block_vals)

        # Componente imaginaria de la perturbación (fase del bloque)
        h_block = hashlib.sha3_256(block + block_num.to_bytes(4, "big")).digest()
        block_phase = np.frombuffer(h_block[:32], dtype=np.uint8).astype(float) / 255.0
        block_phase_interp = np.interp(
            np.linspace(0, 31, _HASH_N), np.arange(32), block_phase
        )

        # El bloque entra directamente al campo
        psi = psi + DELTA_F * (block_interp + 1j * block_phase_interp)

        # Evolucionar — la SPDE mezcla el bloque en toda la trayectoria
        h_step = hashlib.sha3_256(block + block_num.to_bytes(4, "big") + b"STEP").digest()
        for step in range(_HASH_STEPS):
            psi = step_mfsu(psi, h_step, step, dt=_HASH_DT)

        block_num += 1

    # Condensar el estado final
    state_bytes = (
        (np.real(psi) * 1e10).astype(np.int64).tobytes()
        + (np.imag(psi) * 1e10).astype(np.int64).tobytes()
    )
    return hashlib.sha3_512(state_bytes).hexdigest()
