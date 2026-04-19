"""
Ejemplo de uso de axis-vault como librería Python.

Ejecutar:
    pip install axis-vault
    python examples/encrypt_file.py
"""

import os
import time
from axis.crypto import encrypt, decrypt
from axis.hash_mfsu import digest
from axis.totp import generate, verify
from axis.kdf import derive


def demo_encrypt_decrypt():
    print("=" * 60)
    print("  Demo: Cifrado y descifrado MFSU v3")
    print("=" * 60)

    mensaje = b"Hola desde el Modelo Fractal-Estocástico Unificado!"
    password = "mi_contraseña_segura_2025"

    print(f"\nMensaje original : {mensaje.decode()}")
    print(f"Contraseña       : {password}")

    # Cifrar
    print("\nCifrando (KDF memory-hard ~0.5 s)...", end=" ", flush=True)
    t0 = time.perf_counter()
    blob = encrypt(mensaje, password)
    elapsed = time.perf_counter() - t0
    print(f"listo en {elapsed:.2f} s")
    print(f"Blob cifrado     : {len(blob)} bytes ({len(blob) - len(mensaje)} de overhead)")
    print(f"Primeros 12 bytes: {blob[:12].hex()} (MAGIC + VERSION + inicio IV)")

    # Descifrar
    print("\nDescifrando...", end=" ", flush=True)
    t0 = time.perf_counter()
    recovered = decrypt(blob, password)
    elapsed = time.perf_counter() - t0
    print(f"listo en {elapsed:.2f} s")
    print(f"Recuperado       : {recovered.decode()}")
    assert recovered == mensaje, "¡Error! El round-trip falló."
    print("✓ Round-trip verificado.")

    # Contraseña incorrecta
    print("\nProbando contraseña incorrecta...")
    try:
        decrypt(blob, "contraseña_equivocada")
        print("✗ Error: debería haber fallado.")
    except ValueError as e:
        print(f"✓ Rechazada correctamente: {e}")


def demo_hash():
    print("\n" + "=" * 60)
    print("  Demo: Hash Merkle-Damgård Fractal")
    print("=" * 60)

    textos = [
        b"hola mundo",
        b"hola Mundo",   # 1 carácter distinto
        b"hola mundo ",  # espacio extra
    ]

    hashes = []
    for t in textos:
        h = digest(t)
        hashes.append(h)
        print(f"\n  Texto  : {t!r}")
        print(f"  Hash   : {h[:32]}…")

    # Calcular avalanche entre los dos primeros
    b1 = bin(int(hashes[0], 16))[2:].zfill(512)
    b2 = bin(int(hashes[1], 16))[2:].zfill(512)
    diff = sum(a != b for a, b in zip(b1, b2))
    print(f"\n  Avalanche (1 char): {diff}/512 bits distintos ({diff/512*100:.1f}%)")


def demo_totp():
    print("\n" + "=" * 60)
    print("  Demo: TOTP Fractal anti-replay")
    print("=" * 60)

    secreto = "MFSU_DEMO_SECRET_v3"
    code, expires, prev, nxt = generate(secreto)

    print(f"\n  Código actual  : {code}")
    print(f"  Expira en      : {expires} s")
    print(f"  Ventana ant.   : {prev}")
    print(f"  Ventana sig.   : {nxt}")

    # Verificar
    ok = verify(secreto, code)
    print(f"\n  Verificar '{code}': {'✓ válido' if ok else '✗ inválido'}")
    ok_wrong = verify(secreto, "000000")
    print(f"  Verificar '000000': {'✓ válido' if ok_wrong else '✗ inválido'}")


def demo_kdf():
    print("\n" + "=" * 60)
    print("  Demo: KDF Memory-Hard")
    print("=" * 60)

    password = "contraseña_demo"
    salt = os.urandom(16)

    print(f"\n  Derivando clave de 96 bytes (KDF memory-hard)...", end=" ", flush=True)
    t0 = time.perf_counter()
    key = derive(password, salt, key_len=96)
    elapsed = time.perf_counter() - t0
    print(f"listo en {elapsed:.2f} s")
    print(f"  Clave (hex)    : {key.hex()[:48]}…")
    print(f"  Longitud       : {len(key)} bytes")

    # Reproductibilidad
    key2 = derive(password, salt, key_len=96)
    print(f"  Reproducible   : {'✓ sí' if key == key2 else '✗ no'}")

    # Sensibilidad al salt
    key3 = derive(password, os.urandom(16), key_len=96)
    diff = sum(a != b for a, b in zip(key, key3))
    print(f"  Salt distinto  : {diff}/96 bytes distintos ({diff/96*100:.0f}%)")


if __name__ == "__main__":
    demo_encrypt_decrypt()
    demo_hash()
    demo_totp()
    demo_kdf()
    print("\n" + "=" * 60)
    print("  Todos los demos completados exitosamente.")
    print("=" * 60)
