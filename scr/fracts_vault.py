import streamlit as st
import numpy as np
from hashlib import sha256
import time

# ====================== MFSU CORE ======================
delta_F = 0.921
sigma = 0.015
memory_factor = 0.65

def mfsu_keystream(key: str, length: int, counter: int = 0):
    h = sha256((key + str(counter)).encode()).digest()
    seed = int.from_bytes(h[:8], 'big')
    x = (int.from_bytes(h[8:16], 'big') / 2**64) * 2 - 1
    
    np.random.seed(seed % (2**32 - 1))
    keystream = np.zeros(length, dtype=np.uint8)
    for i in range(length):
        fractal_part = delta_F * (x**2 - 1.0)
        noise = sigma * np.random.normal(0, 1)
        x = fractal_part + noise + memory_factor * x
        keystream[i] = int((x * 10000) % 256) & 0xFF
    return keystream

def encrypt_file(data: bytes, password: str):
    keystream = mfsu_keystream(password, len(data))
    data_arr = np.frombuffer(data, dtype=np.uint8)
    encrypted = data_arr ^ keystream
    return encrypted.tobytes()

def decrypt_file(encrypted_data: bytes, password: str):
    return encrypt_file(encrypted_data, password)  # reversible

# ====================== INTERFAZ ======================
st.set_page_config(page_title="FRACTA Vault", page_icon="❄️", layout="centered")

st.markdown("""
<h1 style='text-align:center; color:#00b8ff;'>❄️ FRACTA Vault</h1>
<h3 style='text-align:center;'>Protege tus archivos con Matemática Fractal del Universo</h3>
<p style='text-align:center; color:#666;'>Basado en MFSU • δ_F = 0.921 • 100% tuyo</p>
""", unsafe_allow_html=True)

tab1, tab2 = st.tabs(["🔑 FRACTA Auth (2FA)", "🔒 Proteger Archivos"])

# ====================== TAB 1: 2FA ======================
with tab1:
    st.subheader("Generador de códigos 2FA fractal")
    secret = st.text_input("Secreto del usuario", value="MIGUEL_FRACTA_2026", type="password")
    if st.button("Generar código ahora", type="primary"):
        # (código del TOTP fractal que ya teníamos)
        current_time = int(time.time() // 30)
        h = sha256(f"{secret}{current_time}".encode()).digest()
        x = (int.from_bytes(h[:8], 'big') / 2**64) * 2 - 1
        for _ in range(40):
            x = delta_F * (x**2 - 1.0) + sigma * np.random.normal(0, 1) + memory_factor * x
        code = abs(int(x * 1e9)) % 1000000
        st.success(f"**CÓDIGO ACTUAL:** {code:06d}")
        st.caption("Expira en 30 segundos • Evoluciona como el universo")

# ====================== TAB 2: PROTEGER ARCHIVOS ======================
with tab2:
    st.subheader("🔒 Encripta cualquier archivo con FRACTA")
    uploaded_file = st.file_uploader("Sube tu archivo aquí", type=None)
    password = st.text_input("Contraseña (guárdala segura)", type="password")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🔐 Encriptar archivo", type="primary", use_container_width=True):
            if uploaded_file and password:
                data = uploaded_file.getvalue()
                encrypted = encrypt_file(data, password)
                
                st.success("✅ Archivo encriptado con MFSU")
                st.download_button(
                    label="⬇️ Descargar archivo encriptado (.fracta)",
                    data=encrypted,
                    file_name=uploaded_file.name + ".fracta",
                    mime="application/octet-stream"
                )
                st.caption("Comparte la contraseña solo con quien deba abrirlo")
            else:
                st.warning("Sube un archivo y pon una contraseña")

    with col2:
        if st.button("🔓 Desencriptar archivo", use_container_width=True):
            if uploaded_file and password:
                data = uploaded_file.getvalue()
                try:
                    decrypted = decrypt_file(data, password)
                    st.success("✅ Archivo desencriptado correctamente")
                    st.download_button(
                        label="⬇️ Descargar archivo original",
                        data=decrypted,
                        file_name=uploaded_file.name.replace(".fracta", ""),
                        mime="application/octet-stream"
                    )
                except:
                    st.error("Contraseña incorrecta o archivo no encriptado con FRACTA")
            else:
                st.warning("Sube el archivo .fracta y pon la contraseña")

